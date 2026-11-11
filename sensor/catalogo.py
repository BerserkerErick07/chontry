"""Catálogo que el sensor necesita para decidir: reglas, configuración, lista blanca,
activos protegidos, segmentos, switches y contenciones activas.

Se recarga de la BD cada minuto y se guarda cifrado en disco: si el sensor
arranca sin conexión, decide con la última copia conocida.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

from comun.cripto import Cifrador
from comun.reglas_base import CONFIG_BASE, REGLAS_BASE

log = logging.getLogger("chontry.sensor")
ESTADOS_ACTIVOS = ("propuesta", "aprobada", "aplicada", "por_revertir")


class Catalogo:
    def __init__(self, sensor_id: str | None = None):
        self.sensor_id = sensor_id
        self.origen = "base"
        self.reglas = {r["codigo"]: {**r, "habilitada": True} for r in REGLAS_BASE}
        self.config = dict(CONFIG_BASE)
        self.lista_blanca: list[dict] = []
        self.activos: dict[str, dict] = {}          # mac -> datos
        self.protegidos_ip: set[str] = set()
        self.segmentos: list[dict] = []
        self.switches: dict[int, dict] = {}
        self.sensor: dict = {}
        self.contenidos: set[str] = set()           # MACs con contención activa
        self._candado = threading.Lock()

    # ------------------------------------------------------------- carga
    def cargar(self, conexion) -> None:
        with conexion.cursor() as cur:
            cur.execute("""select codigo, nombre, categoria, severidad_base::text, accion::text,
                                  coalesce(mitre_tecnica, ''), parametros, habilitada
                           from chontry.reglas_deteccion""")
            reglas = {f[0]: {"codigo": f[0], "nombre": f[1], "categoria": f[2], "severidad": f[3], "accion": f[4],
                             "mitre": f[5], "parametros": f[6], "habilitada": f[7]} for f in cur.fetchall()}
            cur.execute("select clave, valor from chontry.configuracion")
            config = {**CONFIG_BASE, **dict(cur.fetchall())}
            cur.execute("""select host(red) || '/' || masklen(red), mac::text, r.codigo, expira_en
                           from chontry.lista_blanca l left join chontry.reglas_deteccion r on r.id = l.regla_id
                           where l.red is not null or l.mac is not null""")
            blanca = [{"red": f[0], "mac": f[1], "regla": f[2], "expira": f[3].isoformat() if f[3] else None}
                      for f in cur.fetchall()]
            cur.execute("""select a.mac::text, host(a.ip), a.protegido, a.switch_id, a.puerto_switch, a.vlan_actual
                           from chontry.activos a""")
            activos = {f[0]: {"ip": f[1], "protegido": f[2], "switch_id": f[3], "puerto": f[4], "vlan": f[5]}
                       for f in cur.fetchall()}
            cur.execute("select id, host(red) || '/' || masklen(red), vlan_id, tipo::text from chontry.segmentos_red")
            segmentos = [{"id": f[0], "red": f[1], "vlan": f[2], "tipo": f[3]} for f in cur.fetchall()]
            cur.execute("""select id, nombre, host(ip_gestion), fabricante, credencial_ref, huella_ssh_host,
                                  vlan_cuarentena, puerto_ssh, habilitado, puerto_span from chontry.switches""")
            switches = {f[0]: {"id": f[0], "nombre": f[1], "ip": f[2], "fabricante": f[3], "credencial_ref": f[4],
                               "huella": f[5], "vlan_cuarentena": f[6], "puerto_ssh": f[7], "habilitado": f[8],
                               "puerto_span": f[9]}
                        for f in cur.fetchall()}
            sensor = {}
            if self.sensor_id:
                cur.execute("""select id::text, nombre, interfaz_captura, filtro_bpf, switch_id
                               from chontry.sensores where id = %s""", (self.sensor_id,))
                fila = cur.fetchone()
                if fila is None:
                    raise ValueError("CHONTRY_SENSOR_ID no corresponde a ningún sensor registrado")
                sensor = {"id": fila[0], "nombre": fila[1], "interfaz": fila[2], "filtro": fila[3], "switch_id": fila[4]}
            cur.execute("""select a.mac::text from chontry.contenciones c join chontry.activos a on a.id = c.activo_id
                           where c.estado = any(%s::chontry.estado_contencion[])""", (list(ESTADOS_ACTIVOS),))
            contenidos = {f[0] for f in cur.fetchall()}
        with self._candado:
            self.reglas, self.config, self.lista_blanca = reglas, config, blanca
            self.activos.update(activos)
            self.protegidos_ip = {d["ip"] for d in activos.values() if d["protegido"] and d["ip"]}
            self.segmentos, self.switches, self.sensor = segmentos, switches, sensor
            self.contenidos = contenidos | {m for m in self.contenidos if m not in activos}
            self.origen = "bd"

    def guardar_cache(self, ruta: Path, cifrador: Cifrador | None) -> None:
        if cifrador is None:
            return
        datos = json.dumps({"reglas": self.reglas, "config": self.config, "lista_blanca": self.lista_blanca,
                            "activos": self.activos, "segmentos": self.segmentos,
                            "switches": {str(k): v for k, v in self.switches.items()}, "sensor": self.sensor,
                            "contenidos": sorted(self.contenidos)}, default=str).encode()
        ruta.write_bytes(cifrador.cifrar_texto("catalogo", datos.decode()))

    def cargar_cache(self, ruta: Path, cifrador: Cifrador | None) -> bool:
        if cifrador is None or not ruta.is_file():
            return False
        try:
            datos = json.loads(cifrador.descifrar_texto("catalogo", ruta.read_bytes()))
        except Exception:   # noqa: BLE001 - caché corrupta o de otra clave: se ignora
            log.warning("No se pudo leer el catálogo en caché; se usan las reglas base")
            return False
        self.reglas, self.config, self.lista_blanca = datos["reglas"], datos["config"], datos["lista_blanca"]
        self.activos, self.segmentos, self.sensor = datos["activos"], datos["segmentos"], datos["sensor"]
        self.switches = {int(k): v for k, v in datos["switches"].items()}
        self.protegidos_ip = {d["ip"] for d in self.activos.values() if d.get("protegido") and d.get("ip")}
        self.contenidos = set(datos["contenidos"])
        self.origen = "cache"
        return True

    # ---------------------------------------------------------- consultas
    def arp_conocidas(self) -> dict[str, str]:
        """IP -> MAC registrada de los activos protegidos: referencia para detectar suplantación."""
        return {d["ip"]: mac for mac, d in self.activos.items() if d.get("protegido") and d.get("ip")}

    def reglas_detector(self) -> dict[str, dict]:
        return {c: {"habilitada": r["habilitada"], "parametros": r["parametros"]} for c, r in self.reglas.items()}

    def en_lista_blanca(self, ip: str, mac: str | None, codigo: str, ahora: datetime | None = None) -> bool:
        ahora = ahora or datetime.now(timezone.utc)
        direccion = ipaddress.ip_address(ip)
        for entrada in self.lista_blanca:
            if entrada["regla"] and entrada["regla"] != codigo:
                continue
            if entrada["expira"] and datetime.fromisoformat(entrada["expira"]) <= ahora:
                continue
            if entrada["red"] and direccion in ipaddress.ip_network(entrada["red"], strict=False):
                return True
            if entrada["mac"] and mac and entrada["mac"].lower() == mac.lower():
                return True
        return False

    def es_protegido(self, ip: str, mac: str | None) -> bool:
        activo = self.activos.get(mac or "")
        return ip in self.protegidos_ip or bool(activo and activo.get("protegido"))

    def segmento_de(self, ip: str) -> dict | None:
        direccion = ipaddress.ip_address(ip)
        return next((s for s in self.segmentos if direccion in ipaddress.ip_network(s["red"])), None)

    def switch_para(self, mac: str | None) -> dict | None:
        activo = self.activos.get(mac or "") or {}
        ident = activo.get("switch_id") or self.sensor.get("switch_id")
        if ident and ident in self.switches:
            return self.switches[ident]
        habilitados = [s for s in self.switches.values() if s.get("habilitado", True)]
        return habilitados[0] if len(habilitados) == 1 else None

    def entero(self, clave: str) -> int:
        return int(self.config.get(clave, CONFIG_BASE.get(clave, 0)))
