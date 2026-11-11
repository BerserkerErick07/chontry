"""Orquestación del sensor: captura, detección, publicación, contención y tareas periódicas."""
from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone

import psycopg

from comun.config import carpeta_datos
from comun.cripto import Cifrador
from comun.errores import manejar_error
from sensor import VERSION
from sensor.catalogo import Catalogo
from sensor.contencion import Ejecutor
from sensor.detector import Detector
from sensor.motor import Motor
from sensor.publicador import BufferLocal, Publicador

log = logging.getLogger("chontry.sensor")


class Servicio:
    def __init__(self, fabrica_conexion, sensor_id: str | None, cifrador: Cifrador | None, con_bd: bool = True):
        self.fabrica = fabrica_conexion
        self.sensor_id = sensor_id
        self.cifrador = cifrador
        self.con_bd = con_bd
        self.catalogo = Catalogo(sensor_id)
        self._detener = threading.Event()
        self._paquetes = 0
        self._bytes = 0
        self._ultimo_ts = 0.0
        datos = carpeta_datos()
        self._ruta_cache = datos / "catalogo.cache"
        self.publicador = (Publicador(fabrica_conexion, BufferLocal(datos / "sensor_buffer.db", cifrador))
                           if con_bd else PublicadorNulo())
        self._cargar_catalogo(inicial=True)
        self.ejecutor = Ejecutor(str(self.catalogo.config.get("contencion.modo_ejecucion", "simulado")))
        self.detector = Detector(self.catalogo.reglas_detector(), self.catalogo.arp_conocidas())
        self.motor = Motor(self.catalogo, self.publicador, self.ejecutor, cifrador, sensor_id,
                           actor=self.catalogo.sensor.get("nombre", "sensor"))

    # ------------------------------------------------------------ catálogo
    def _cargar_catalogo(self, inicial: bool = False) -> None:
        if not self.con_bd:
            return
        try:
            with self.fabrica() as conexion:
                self.catalogo.cargar(conexion)
            self.catalogo.guardar_cache(self._ruta_cache, self.cifrador)
            if inicial:
                log.info("Catálogo cargado de la BD: %d reglas, modo de contención %s", len(self.catalogo.reglas),
                         self.catalogo.config.get("contencion.modo_ejecucion"))
        except ValueError:
            raise
        except Exception as exc:  # noqa: BLE001 - sin conexión se trabaja con la caché
            if inicial:
                usado = "la caché local" if self.catalogo.cargar_cache(self._ruta_cache, self.cifrador) else "las reglas base"
                log.warning("No se pudo cargar el catálogo (%s); se usan %s", type(exc).__name__, usado)
        if hasattr(self, "detector"):
            self.detector.actualizar_reglas(self.catalogo.reglas_detector(), self.catalogo.arp_conocidas())

    # ------------------------------------------------------------ paquetes
    def procesar(self, pkt) -> None:
        self._paquetes += 1
        self._bytes += len(pkt)
        self._ultimo_ts = float(pkt.time)
        for deteccion in self.detector.procesar(pkt):
            self.motor.manejar(deteccion)
        if self._paquetes % 200 == 0:
            for mac, ip in list(self.detector.ip_de_mac.items())[-50:]:
                self.motor.observar_activo(mac, ip, self._ultimo_ts)
            self.motor.tick(self._ultimo_ts)

    # ------------------------------------------------------- tareas en hilo
    def iniciar_tareas(self, con_contencion: bool = True) -> None:
        self.publicador.start()
        if not self.con_bd:
            return
        threading.Thread(target=self._bucle, args=(60, self._cargar_catalogo), name="catalogo", daemon=True).start()
        threading.Thread(target=self._bucle, args=(self.catalogo.entero("sensor.heartbeat_seg"), self._heartbeat),
                         name="heartbeat", daemon=True).start()
        threading.Thread(target=self._bucle, args=(self.catalogo.entero("sensor.metricas_seg"), self._metrica),
                         name="metricas", daemon=True).start()
        if con_contencion:
            threading.Thread(target=self._bucle, args=(5, self._atender_contenciones),
                             name="contencion", daemon=True).start()
        self._heartbeat()

    def _bucle(self, segundos: int, tarea) -> None:
        while not self._detener.wait(max(1, int(segundos))):
            try:
                tarea()
            except Exception as exc:  # noqa: BLE001 - una tarea periódica fallida no detiene el sensor
                manejar_error(exc, f"tarea periódica {tarea.__name__}")

    def _heartbeat(self, estado: str = "activo") -> None:
        if self.sensor_id:
            self.publicador.enviar("heartbeat", sensor_id=self.sensor_id, estado=estado, version=VERSION)

    def _metrica(self) -> None:
        if not self.sensor_id:
            return
        intervalo = max(1, self.catalogo.entero("sensor.metricas_seg"))
        paquetes, bytes_, self._paquetes_m, self._bytes_m = self._paquetes - getattr(self, "_paquetes_m", 0), \
            self._bytes - getattr(self, "_bytes_m", 0), self._paquetes, self._bytes
        self.publicador.enviar("metrica", sensor_id=self.sensor_id, ts=datetime.now(timezone.utc).isoformat(),
                               pps=paquetes // intervalo, bps=bytes_ * 8 // intervalo, descartados=0,
                               hosts=len(self.detector.ip_de_mac))

    def _atender_contenciones(self) -> None:
        """Ejecuta en el switch lo que pidió un administrador: aprobar, liberar y vencimiento del TTL."""
        consulta = """
            select c.uid::text, c.estado::text, c.puerto_switch, c.vlan_origen, c.vlan_destino, a.mac::text,
                   s.id, s.nombre, host(s.ip_gestion), s.fabricante, s.credencial_ref, s.huella_ssh_host,
                   s.vlan_cuarentena, s.puerto_ssh
            from chontry.contenciones c
            join chontry.switches s on s.id = c.switch_id
            join chontry.activos a on a.id = c.activo_id
            where (c.estado in ('aprobada', 'por_revertir') or (c.estado = 'aplicada' and c.expira_en < now()))
              and (%(switch)s::int is null or c.switch_id = %(switch)s::int)
            order by c.id"""
        try:
            with self.fabrica() as conexion, conexion.cursor() as cur:
                cur.execute(consulta, {"switch": self.catalogo.sensor.get("switch_id")})
                pendientes = cur.fetchall()
        except psycopg.OperationalError:
            return
        for uid, estado, puerto, vlan_origen, vlan_destino, mac, *s in pendientes:
            switch = {"id": s[0], "nombre": s[1], "ip": s[2], "fabricante": s[3], "credencial_ref": s[4],
                      "huella": s[5], "vlan_cuarentena": s[6], "puerto_ssh": s[7]}
            ahora = datetime.now(timezone.utc).isoformat()
            if estado == "aprobada":
                ok, salida = self.ejecutor.aplicar(switch, puerto, vlan_destino)
                self.publicador.enviar("contencion_estado", uid=uid, estado="aplicada" if ok else "fallida",
                                       aplicada_en=ahora if ok else None, salida=salida if ok else None,
                                       error=None if ok else salida)
                if ok:
                    self.catalogo.contenidos.add(mac)
            else:
                ok, salida = self.ejecutor.revertir(switch, puerto, vlan_origen)
                nuevo = "revertida" if estado == "por_revertir" else "expirada"
                if ok:
                    self.publicador.enviar("contencion_estado", uid=uid, estado=nuevo, revertida_en=ahora, salida=salida)
                    self.catalogo.contenidos.discard(mac)
                else:
                    log.error("No se pudo liberar %s en %s; se reintenta", mac, switch["nombre"])
            log.info("Contención %s: %s -> %s", uid[:8], estado, "ok" if ok else "error")

    # -------------------------------------------------------------- cierre
    def detener(self) -> None:
        self._detener.set()
        self.motor.cerrar()
        self._heartbeat("detenido")
        self.publicador.detener()
        log.info("Sensor detenido. %s · escritas=%d descartadas=%d pendientes_en_buffer=%d",
                 self.motor.resumen(), self.publicador.escritas, self.publicador.descartadas,
                 self.publicador.buffer.pendientes())


class PublicadorNulo:
    """Modo --sin-bd: las operaciones se descartan (solo se muestran las detecciones)."""
    escritas = descartadas = 0

    class buffer:   # noqa: N801 - imita la interfaz de BufferLocal
        @staticmethod
        def pendientes() -> int:
            return 0

    def enviar(self, operacion: str, /, **datos) -> None:
        pass

    def start(self) -> None:
        pass

    def detener(self, esperar: float = 0) -> None:
        pass
