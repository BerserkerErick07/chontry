"""Motor de decisión del sensor: agrega detecciones en alertas y decide la respuesta.

Reglas de respuesta (las mismas que aplica la consola y la base de datos):
  - lista blanca vigente           -> se ignora
  - accion = alertar               -> solo alerta
  - activo protegido               -> nunca se contiene (se audita)
  - ya hay contención activa       -> no se duplica
  - accion = contener              -> contención automática con TTL, si no se superó el tope por hora
  - accion = proponer_contencion   -> propuesta que debe aprobar un administrador
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from scapy.utils import wrpcap

from comun.cripto import Cifrador
from sensor.catalogo import Catalogo
from sensor.contencion import Ejecutor
from sensor.detector import Deteccion

log = logging.getLogger("chontry.sensor")
PUNTAJE_BASE = {"info": 20, "baja": 35, "media": 55, "alta": 75, "critica": 90}
INTERVALO_ACTUALIZACION = 10.0   # segundos mínimos entre actualizaciones de una misma alerta


class _Memoria(io.BytesIO):
    """wrpcap cierra el archivo al terminar; aquí se conserva para leer los bytes."""

    def close(self) -> None:
        pass


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat()


@dataclass
class AlertaAbierta:
    uid: str
    codigo: str
    ip: str
    mac: str | None
    severidad: str
    puntaje: int
    primera: float
    ultima: float
    conteo: int = 1
    puertos: set[int] = field(default_factory=set)
    destinos: set[str] = field(default_factory=set)
    enviada: float = 0.0
    pendiente: bool = False


class Motor:
    def __init__(self, catalogo: Catalogo, publicador, ejecutor: Ejecutor, cifrador: Cifrador | None,
                 sensor_id: str | None, actor: str = "sensor"):
        self.catalogo = catalogo
        self.publicador = publicador
        self.ejecutor = ejecutor
        self.cifrador = cifrador
        self.sensor_id = sensor_id
        self.actor = actor
        self.abiertas: dict[tuple[str, str], AlertaAbierta] = {}
        self._automaticas: deque[float] = deque()
        self._activos_vistos: dict[str, tuple[str, float]] = {}   # mac -> (ip, último envío)
        self._switch = ThreadPoolExecutor(max_workers=1, thread_name_prefix="switch")
        self.estadisticas = {"detecciones": 0, "alertas": 0, "contenciones": 0, "ignoradas": 0}

    # ---------------------------------------------------------- inventario
    def observar_activo(self, mac: str, ip: str, ts: float) -> None:
        anterior = self._activos_vistos.get(mac)
        if anterior and anterior[0] == ip and ts - anterior[1] < 300:
            return
        self._activos_vistos[mac] = (ip, ts)
        segmento = self.catalogo.segmento_de(ip)
        self.publicador.enviar("activo", mac=mac, ip=ip, segmento_id=segmento["id"] if segmento else None,
                               visto=_iso(ts))
        self.catalogo.activos.setdefault(mac, {"ip": ip, "protegido": False, "switch_id": None,
                                               "puerto": None, "vlan": segmento["vlan"] if segmento else None})

    # ------------------------------------------------------------ alertas
    def manejar(self, d: Deteccion) -> None:
        self.estadisticas["detecciones"] += 1
        regla = self.catalogo.reglas.get(d.codigo)
        if regla is None or not regla.get("habilitada", True):
            return
        if self.catalogo.en_lista_blanca(d.ip_origen, d.mac_origen, d.codigo):
            self.estadisticas["ignoradas"] += 1
            log.info("%s desde %s ignorada: está en la lista blanca", d.codigo, d.ip_origen)
            return
        if d.mac_origen:
            self.observar_activo(d.mac_origen, d.ip_origen, d.ts)

        ventana = self.catalogo.entero("deteccion.agregacion_seg")
        clave = (d.codigo, d.ip_origen)
        alerta = self.abiertas.get(clave)
        if alerta and d.ts - alerta.ultima <= ventana:
            alerta.conteo += 1
            alerta.ultima = d.ts
            alerta.puertos |= d.puertos
            alerta.destinos |= d.destinos
            alerta.puntaje = min(100, alerta.puntaje + 2)
            alerta.pendiente = True
            if d.ts - alerta.enviada >= INTERVALO_ACTUALIZACION:
                self._enviar_actualizacion(alerta)
            return

        alerta = AlertaAbierta(str(uuid.uuid4()), d.codigo, d.ip_origen, d.mac_origen, regla["severidad"],
                               PUNTAJE_BASE[regla["severidad"]], d.ts, d.ts, 1, set(d.puertos), set(d.destinos),
                               enviada=d.ts)
        self.abiertas[clave] = alerta
        self.estadisticas["alertas"] += 1
        self.publicador.enviar(
            "alerta_crear", uid=alerta.uid, sensor_id=self.sensor_id, codigo=d.codigo, severidad=alerta.severidad,
            puntaje=alerta.puntaje, ip=d.ip_origen, mac=d.mac_origen,
            ip_destino=next(iter(d.destinos)) if len(d.destinos) == 1 else None,
            destinos=sorted(alerta.destinos), puertos=sorted(alerta.puertos), protocolo=d.protocolo,
            resumen=f"{regla['nombre']}: {d.descripcion}"[:300], conteo=1, primera=_iso(d.ts), ultima=_iso(d.ts),
            detalle={"descripcion": d.descripcion, "parametros_regla": regla["parametros"],
                     "paquetes": [p.summary() for p in d.paquetes[:10]], "sensor": self.catalogo.sensor.get("nombre")})
        self._evidencia(alerta, d)
        self._responder(alerta, regla)

    def _enviar_actualizacion(self, alerta: AlertaAbierta) -> None:
        alerta.enviada = alerta.ultima
        alerta.pendiente = False
        self.publicador.enviar("alerta_actualizar", uid=alerta.uid, conteo=alerta.conteo, ultima=_iso(alerta.ultima),
                               puntaje=alerta.puntaje, puertos=sorted(alerta.puertos)[:500],
                               destinos=sorted(alerta.destinos)[:500])

    def _evidencia(self, alerta: AlertaAbierta, d: Deteccion) -> None:
        """Paquetes de la ráfaga en formato pcap, cifrados con AES-256-GCM antes de salir del sensor."""
        if self.cifrador is None or not d.paquetes:
            return
        memoria = _Memoria()
        wrpcap(memoria, d.paquetes)
        claro = memoria.getvalue()
        nonce, cifrado = self.cifrador.cifrar("evidencias", claro, alerta.uid.encode())
        self.publicador.enviar("evidencia", alerta_uid=alerta.uid, tipo="pcap",
                               contenido=base64.b64encode(cifrado).decode(), nonce=base64.b64encode(nonce).decode(),
                               id_clave=self.cifrador.id_clave,
                               sha256=base64.b64encode(hashlib.sha256(claro).digest()).decode(), tamano=len(claro))

    # ---------------------------------------------------------- respuesta
    def _auditar(self, accion: str, entidad: str, entidad_id: str, detalle: dict) -> None:
        self.publicador.enviar("auditar", actor=self.actor, accion=accion, entidad=entidad,
                               entidad_id=entidad_id, detalle=detalle)

    def _responder(self, alerta: AlertaAbierta, regla: dict) -> None:
        if regla["accion"] == "alertar":
            return
        if self.catalogo.es_protegido(alerta.ip, alerta.mac):
            self._auditar("contencion_omitida", "activos", alerta.ip, {"motivo": "activo protegido", "alerta": alerta.uid})
            return
        if not alerta.mac or alerta.mac in self.catalogo.contenidos:
            return
        switch = self.catalogo.switch_para(alerta.mac)
        segmento = self.catalogo.segmento_de(alerta.ip)
        activo = self.catalogo.activos.get(alerta.mac, {})
        vlan_origen = activo.get("vlan") or (segmento["vlan"] if segmento else None)
        if switch is None or vlan_origen is None:
            self._auditar("contencion_imposible", "alertas", alerta.uid,
                          {"motivo": "sin switch registrado" if switch is None else "VLAN de origen desconocida",
                           "ip": alerta.ip})
            return
        self.catalogo.contenidos.add(alerta.mac)
        automatica = regla["accion"] == "contener"
        motivo = f"{regla['codigo']} {regla['nombre']}"
        ahora = time.time()
        while self._automaticas and ahora - self._automaticas[0] > 3600:
            self._automaticas.popleft()
        if automatica and len(self._automaticas) >= self.catalogo.entero("contencion.max_por_hora"):
            automatica = False
            motivo += " (tope de contenciones automáticas alcanzado: requiere aprobación)"
        if automatica:
            self._automaticas.append(ahora)
        self._switch.submit(self._contener, alerta, switch, vlan_origen, automatica, motivo[:300])

    def _contener(self, alerta: AlertaAbierta, switch: dict, vlan_origen: int, automatica: bool, motivo: str) -> None:
        try:
            puerto = self.catalogo.activos.get(alerta.mac, {}).get("puerto") or \
                self.ejecutor.resolver_puerto(switch, alerta.mac)
            if puerto is None or puerto == switch.get("puerto_span"):
                self.catalogo.contenidos.discard(alerta.mac)
                motivo_fallo = ("no se encontró el puerto del host en el switch" if puerto is None
                                else "el puerto es el SPAN del sensor; aislarlo dejaría ciego al IDS")
                self._auditar("contencion_imposible", "alertas", alerta.uid, {"motivo": motivo_fallo, "ip": alerta.ip})
                return
            datos = {"uid": str(uuid.uuid4()), "alerta_uid": alerta.uid, "mac": alerta.mac, "switch_id": switch["id"],
                     "puerto": puerto, "vlan_origen": vlan_origen, "vlan_destino": switch["vlan_cuarentena"],
                     "motivo": motivo, "aplicada_en": None, "expira_en": None, "salida": None, "error": None,
                     "modo": "automatica" if automatica else "manual", "estado": "propuesta"}
            if automatica:
                ok, salida = self.ejecutor.aplicar(switch, puerto, switch["vlan_cuarentena"])
                ahora = datetime.now(timezone.utc)
                datos.update(estado="aplicada" if ok else "fallida", salida=salida if ok else None,
                             error=None if ok else salida, aplicada_en=ahora.isoformat() if ok else None,
                             expira_en=(ahora + timedelta(minutes=self.catalogo.entero("contencion.ttl_minutos"))).isoformat()
                             if ok else None)
                if not ok:
                    self.catalogo.contenidos.discard(alerta.mac)
            self.publicador.enviar("contencion_crear", **datos)
            self.estadisticas["contenciones"] += 1
            log.info("Contención %s (%s) para %s en %s %s", datos["estado"], datos["modo"], alerta.ip,
                     switch["nombre"], puerto)
        except Exception as exc:  # noqa: BLE001 - un fallo de contención no detiene la captura
            self.catalogo.contenidos.discard(alerta.mac)
            log.exception("Error al contener %s: %s", alerta.ip, type(exc).__name__)

    # --------------------------------------------------------- mantenimiento
    def tick(self, ahora_paquete: float) -> None:
        """Envía actualizaciones pendientes y olvida alertas cuya ventana de agregación ya pasó."""
        ventana = self.catalogo.entero("deteccion.agregacion_seg")
        for clave, alerta in list(self.abiertas.items()):
            if alerta.pendiente and ahora_paquete - alerta.enviada >= INTERVALO_ACTUALIZACION:
                self._enviar_actualizacion(alerta)
            if ahora_paquete - alerta.ultima > ventana:
                if alerta.pendiente:
                    self._enviar_actualizacion(alerta)
                del self.abiertas[clave]

    def cerrar(self) -> None:
        for alerta in self.abiertas.values():
            if alerta.pendiente:
                self._enviar_actualizacion(alerta)
        self._switch.shutdown(wait=True)

    def resumen(self) -> str:
        return json.dumps(self.estadisticas)
