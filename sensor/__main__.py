"""Punto de entrada del sensor.

    python -m sensor --interfaz eth0            captura en vivo del puerto SPAN
    python -m sensor --pcap captura.pcap        analiza una captura (pruebas, forense)
    python -m sensor --pcap x.pcap --sin-bd     solo muestra las detecciones en pantalla
    python -m sensor --solo-contencion          atiende aprobaciones y liberaciones sin capturar

Variables (.env): CHONTRY_DB_URL (login ct_... del sensor), CHONTRY_SENSOR_ID,
CHONTRY_CLAVE_MAESTRA (cifrado de evidencias y del buffer local).
"""
import argparse
import logging
import os
import signal
import sys
import threading

from comun.config import cargar_env, carpeta_datos
from comun.cripto import ClaveNoDisponible, Cifrador
from comun.db import ConfiguracionInsegura, conectar
from comun.errores import configurar_log
from comun.validacion import EntradaInvalida, validar_filtro_bpf, validar_interfaz_captura

log = logging.getLogger("chontry.sensor")


def _argumentos(argv):
    p = argparse.ArgumentParser(prog="python -m sensor", description="ChonTry · sensor de red")
    origen = p.add_mutually_exclusive_group(required=True)
    origen.add_argument("--interfaz", help="interfaz conectada al puerto SPAN (por defecto la del sensor en la BD)",
                        nargs="?", const="")
    origen.add_argument("--pcap", help="archivo .pcap/.pcapng a analizar")
    origen.add_argument("--solo-contencion", action="store_true", help="solo ejecuta contenciones aprobadas")
    p.add_argument("--filtro", help="filtro BPF (por defecto el del sensor en la BD)")
    p.add_argument("--sin-bd", action="store_true", help="no usa la base de datos: imprime las detecciones")
    p.add_argument("--continuar", action="store_true", help="tras el .pcap sigue atendiendo contenciones")
    p.add_argument("--permitir-root", action="store_true", help="permite ejecutar como root (no recomendado)")
    return p.parse_args(argv)


def _verificar_privilegios(permitir_root: bool) -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0 and not permitir_root:
        sys.exit("Por mínimo privilegio el sensor no corre como root. Use CAP_NET_RAW "
                 "(ver despliegue/chontry-sensor.service) o --permitir-root.")


def _imprimir(motor_manejar):
    def envoltura(deteccion):
        print(f"[{deteccion.codigo}] {deteccion.ip_origen} ({deteccion.mac_origen}) -> "
              f"{len(deteccion.destinos)} destino(s), {len(deteccion.puertos)} puerto(s): {deteccion.descripcion}")
        motor_manejar(deteccion)
    return envoltura


def main(argv=None) -> int:
    args = _argumentos(argv)
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    cargar_env()
    configurar_log(str(carpeta_datos() / "sensor.log"))
    logging.getLogger("chontry").addHandler(logging.StreamHandler(sys.stdout))
    _verificar_privilegios(args.permitir_root)

    try:
        cifrador = Cifrador.desde_entorno()
    except ClaveNoDisponible as exc:
        cifrador = None
        log.warning("%s. Las evidencias no se guardarán.", exc)

    from sensor.servicio import Servicio   # importa scapy: después de configurar el log
    con_bd = not args.sin_bd
    try:
        url = os.environ.get("CHONTRY_DB_URL_SENSOR") or os.environ.get("CHONTRY_DB_URL")
        servicio = Servicio(lambda: conectar(url, aplicacion="chontry-sensor"),
                            os.environ.get("CHONTRY_SENSOR_ID") if con_bd else None, cifrador, con_bd)
    except (ConfiguracionInsegura, ValueError) as exc:
        log.error("Configuración inválida: %s", exc)
        return 2
    if args.sin_bd:
        servicio.motor.manejar = _imprimir(servicio.motor.manejar)

    detener = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: detener.set())
    servicio.iniciar_tareas(con_contencion=con_bd)

    if args.solo_contencion:
        log.info("Atendiendo contenciones aprobadas (Ctrl+C para salir)")
        detener.wait()
    elif args.pcap:
        from scapy.utils import PcapReader
        log.info("Analizando %s", args.pcap)
        with PcapReader(args.pcap) as lector:
            for paquete in lector:
                servicio.procesar(paquete)
                if detener.is_set():
                    break
        servicio.motor.tick(float("inf"))
        log.info("Captura analizada: %d paquetes", servicio._paquetes)
        if args.continuar:
            log.info("Atendiendo contenciones aprobadas (Ctrl+C para salir)")
            detener.wait()
    else:
        try:
            interfaz = validar_interfaz_captura(args.interfaz or servicio.catalogo.sensor.get("interfaz", ""))
            filtro = args.filtro or servicio.catalogo.sensor.get("filtro")
            if filtro:
                validar_filtro_bpf(filtro)
        except EntradaInvalida as exc:
            log.error("%s", exc)
            return 2
        from scapy.sendrecv import AsyncSniffer
        log.info("Capturando en %s con filtro %r (Ctrl+C para salir)", interfaz, filtro)
        captura = AsyncSniffer(iface=interfaz, filter=filtro, prn=servicio.procesar, store=False)
        captura.start()
        while not detener.wait(1):
            servicio.motor.tick(servicio._ultimo_ts)
        captura.stop()
    servicio.detener()
    return 0


if __name__ == "__main__":
    sys.exit(main())
