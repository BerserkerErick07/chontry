"""Estado en memoria de la consola: alertas, contenciones y auditoría.

En el modo demostración reemplaza a la base de datos, pero aplica las mismas
reglas que las migraciones 001-004: autorización por rol, activos protegidos,
tope de contenciones automáticas, TTL y auditoría encadenada con SHA-256.
"""
from __future__ import annotations

import hashlib
import itertools
import json
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from PySide6.QtCore import QObject, Signal

from comun.validacion import (EntradaInvalida, comandos_cuarentena, validar_interfaz_switch,
                              validar_ip, validar_vlan)

SEVERIDADES = ("info", "baja", "media", "alta", "critica")
PUNTAJE_BASE = {"info": 20, "baja": 35, "media": 55, "alta": 75, "critica": 90}
ESTADOS_ABIERTOS = ("nueva", "en_revision")
ESTADOS_ALERTA = ("nueva", "en_revision", "contenida", "falso_positivo", "cerrada")
CONTENCION_ACTIVA = ("propuesta", "aprobada", "aplicada", "por_revertir")

SWITCH_DEMO = "sw-lab-01"
FABRICANTE_DEMO = "cisco_ios"
VLAN_USUARIOS = 20
VLAN_CUARENTENA = 999
GENESIS = b"\x00"


class PermisoDenegado(Exception):
    """La acción requiere un rol que el usuario no tiene."""


@dataclass
class Regla:
    codigo: str
    nombre: str
    categoria: str
    severidad: str
    accion: str
    mitre: str
    parametros: dict
    habilitada: bool = True


@dataclass
class Alerta:
    id: int
    regla: Regla
    severidad: str
    puntaje: int
    ip_origen: str
    mac_origen: str
    primera: datetime
    ultima: datetime
    destinos: set[str] = field(default_factory=set)
    puertos: set[int] = field(default_factory=set)
    conteo: int = 1
    estado: str = "nueva"
    uid: str | None = None
    texto: str = ""

    @property
    def resumen(self) -> str:
        if self.texto:
            return self.texto
        partes = [self.regla.nombre]
        if self.puertos:
            n = len(self.puertos)
            partes.append(f"puerto {next(iter(self.puertos))}" if n == 1 else f"{n} puertos")
        if self.destinos:
            n = len(self.destinos)
            partes.append(f"hacia {next(iter(self.destinos))}" if n == 1 else f"{n} destinos")
        return " · ".join(partes)


@dataclass
class Contencion:
    id: int
    alerta_id: int | None
    ip: str
    mac: str
    puerto: str
    modo: str
    estado: str
    motivo: str
    solicitado_por: str
    creada: datetime
    comandos: list[str]
    switch: str = SWITCH_DEMO
    vlan_origen: int = VLAN_USUARIOS
    vlan_destino: int = VLAN_CUARENTENA
    aprobado_por: str | None = None
    aplicada_en: datetime | None = None
    expira_en: datetime | None = None
    cerrada_en: datetime | None = None
    salida: str | None = None
    error: str | None = None


@dataclass
class EntradaAuditoria:
    id: int
    ts: datetime
    actor: str
    accion: str
    entidad: str
    entidad_id: str
    detalle: dict
    hash_prev: bytes
    hash: bytes = b""

    def calcular_hash(self) -> bytes:
        contenido = "|".join([
            str(self.id), self.ts.isoformat(timespec="microseconds"), self.actor, self.accion,
            self.entidad, self.entidad_id, json.dumps(self.detalle, sort_keys=True, ensure_ascii=False),
        ])
        return hashlib.sha256(self.hash_prev + contenido.encode("utf-8")).digest()


class Estado(QObject):
    """Backend del modo demostración: todo en memoria, con las mismas reglas que la BD."""
    cambio = Signal()
    es_demo = True
    usuario_id = None

    def __init__(self, usuario: str, rol: str, reglas: list[Regla], config: dict, origen: str):
        super().__init__()
        self.usuario = usuario
        self.rol = rol
        self.reglas = {r.codigo: r for r in reglas}
        self.origen_catalogo = origen
        self.ttl = timedelta(minutes=int(config.get("contencion.ttl_minutos", 60)))
        self.max_por_hora = int(config.get("contencion.max_por_hora", 5))
        self.ventana = timedelta(seconds=int(config.get("deteccion.agregacion_seg", 300)))
        self.protegidos = {"10.10.20.1": "Gateway VLAN 20", "10.10.30.10": "DNS / controlador de dominio"}

        self.alertas: list[Alerta] = []
        self.contenciones: list[Contencion] = []
        self.auditoria: list[EntradaAuditoria] = []
        self.pps: deque[int] = deque(maxlen=120)
        self.descartados = 0
        self._id_alerta = itertools.count(1)
        self._id_contencion = itertools.count(1)
        self._id_auditoria = itertools.count(1)
        self._auditar("sistema", "inicio_sesion", "sesiones", usuario, {"rol": rol, "modo": "demostracion"})

    # ------------------------------------------------------------------ util
    @property
    def es_admin(self) -> bool:
        return self.rol == "admin"

    @property
    def puede_operar(self) -> bool:
        return self.rol in ("admin", "analista")

    def notificar(self) -> None:
        self.cambio.emit()

    def _auditar(self, actor: str, accion: str, entidad: str, entidad_id, detalle: dict) -> None:
        prev = self.auditoria[-1].hash if self.auditoria else GENESIS
        entrada = EntradaAuditoria(next(self._id_auditoria), datetime.now(), actor, accion,
                                   entidad, str(entidad_id), detalle, prev)
        entrada.hash = entrada.calcular_hash()
        self.auditoria.append(entrada)

    def _requerir_admin(self, accion: str) -> None:
        if not self.es_admin:
            self._auditar(self.usuario, "acceso_denegado", "contenciones", "-", {"accion": accion})
            self.notificar()
            raise PermisoDenegado(f"Solo un administrador puede {accion}.")

    @staticmethod
    def puerto_de(ip: str) -> str:
        return f"Gi1/0/{int(ip.rsplit('.', 1)[1]) % 48 + 1}"

    def alerta(self, alerta_id: int) -> Alerta:
        return next(a for a in self.alertas if a.id == alerta_id)

    def contencion(self, contencion_id: int) -> Contencion:
        return next(c for c in self.contenciones if c.id == contencion_id)

    def _contencion_activa(self, ip: str) -> Contencion | None:
        return next((c for c in self.contenciones if c.ip == ip and c.estado in CONTENCION_ACTIVA), None)

    # ---------------------------------------------------------- detección
    def agregar_metrica(self, pps: int, descartados: int) -> None:
        self.pps.append(pps)
        self.descartados += descartados

    def registrar_evento(self, codigo: str, ip: str, mac: str, destinos=(), puertos=()) -> Alerta | None:
        regla = self.reglas.get(codigo)
        if regla is None or not regla.habilitada:
            return None
        ahora = datetime.now()
        existente = next((a for a in reversed(self.alertas)
                          if a.regla.codigo == codigo and a.ip_origen == ip
                          and a.estado in ESTADOS_ABIERTOS + ("contenida",)
                          and ahora - a.ultima <= self.ventana), None)
        if existente:
            # Agregación: el mismo origen y la misma regla suman a la misma alerta
            existente.conteo += 1
            existente.ultima = ahora
            existente.destinos.update(destinos)
            existente.puertos.update(puertos)
            existente.puntaje = min(100, existente.puntaje + 2)
            return existente

        alerta = Alerta(next(self._id_alerta), regla, regla.severidad, PUNTAJE_BASE[regla.severidad],
                        ip, mac, ahora, ahora, set(destinos), set(puertos))
        self.alertas.append(alerta)
        self._auditar("sensor-simulado", "INSERT", "alertas", alerta.id,
                      {"regla": codigo, "ip_origen": ip, "severidad": regla.severidad})
        self._responder(alerta)
        return alerta

    def _responder(self, alerta: Alerta) -> None:
        if alerta.regla.accion == "alertar":
            return
        if alerta.ip_origen in self.protegidos:
            self._auditar("sensor-simulado", "contencion_omitida", "activos", alerta.ip_origen,
                          {"motivo": "activo protegido", "alerta": alerta.id})
            return
        if self._contencion_activa(alerta.ip_origen):
            return
        automatica = alerta.regla.accion == "contener"
        motivo = f"{alerta.regla.codigo} {alerta.regla.nombre}"
        if automatica and self._automaticas_ultima_hora() >= self.max_por_hora:
            automatica = False
            motivo += " (tope de contenciones automáticas alcanzado: requiere aprobación)"
        self._crear_contencion(alerta.ip_origen, alerta.mac_origen, self.puerto_de(alerta.ip_origen),
                               VLAN_CUARENTENA, alerta.id, motivo, automatica, "sensor-simulado")

    def _automaticas_ultima_hora(self) -> int:
        limite = datetime.now() - timedelta(hours=1)
        return sum(1 for c in self.contenciones if c.modo == "automatica" and c.creada >= limite)

    def _crear_contencion(self, ip, mac, puerto, vlan, alerta_id, motivo, automatica, solicitante) -> Contencion:
        ahora = datetime.now()
        contencion = Contencion(
            next(self._id_contencion), alerta_id, ip, mac, puerto,
            "automatica" if automatica else "manual",
            "aplicada" if automatica else "propuesta",
            motivo, solicitante, ahora, comandos_cuarentena(FABRICANTE_DEMO, puerto, vlan),
            vlan_destino=vlan,
        )
        if automatica:
            contencion.aplicada_en = ahora
            contencion.expira_en = ahora + self.ttl
            self._marcar_contenida(alerta_id)
        self.contenciones.append(contencion)
        self._auditar(solicitante, "INSERT", "contenciones", contencion.id,
                      {"ip": ip, "modo": contencion.modo, "estado": contencion.estado})
        return contencion

    def _marcar_contenida(self, alerta_id: int | None) -> None:
        if alerta_id is not None:
            self.alerta(alerta_id).estado = "contenida"

    # ------------------------------------------------------------ acciones
    def cambiar_estado_alerta(self, alerta_id: int, estado: str) -> None:
        if estado not in ESTADOS_ALERTA:
            raise EntradaInvalida("Estado de alerta inválido")
        alerta = self.alerta(alerta_id)
        anterior, alerta.estado = alerta.estado, estado
        self._auditar(self.usuario, "UPDATE", "alertas", alerta_id, {"antes": anterior, "despues": estado})
        self.notificar()

    def proponer_manual(self, ip: str, puerto: str, vlan, motivo: str) -> Contencion:
        ip = str(validar_ip(ip.strip()))
        puerto = validar_interfaz_switch(puerto.strip())
        vlan = validar_vlan(vlan)
        motivo = motivo.strip()
        if not 10 <= len(motivo) <= 300:
            raise EntradaInvalida("El motivo debe tener entre 10 y 300 caracteres")
        if vlan == VLAN_USUARIOS:
            raise EntradaInvalida("La VLAN destino no puede ser la misma VLAN de origen")
        if ip in self.protegidos:
            raise EntradaInvalida(f"{ip} es un activo protegido ({self.protegidos[ip]}) y no se puede aislar")
        if self._contencion_activa(ip):
            raise EntradaInvalida("Ese host ya tiene una contención activa")
        mac = next((a.mac_origen for a in reversed(self.alertas) if a.ip_origen == ip), "—")
        contencion = self._crear_contencion(ip, mac, puerto, vlan, None, motivo, False, self.usuario)
        self.notificar()
        return contencion

    def aprobar(self, contencion_id: int) -> None:
        self._requerir_admin("aprobar contenciones")
        contencion = self.contencion(contencion_id)
        if contencion.estado != "propuesta":
            raise EntradaInvalida("Solo se pueden aprobar contenciones pendientes")
        ahora = datetime.now()
        contencion.estado = "aplicada"
        contencion.aprobado_por = self.usuario
        contencion.aplicada_en = ahora
        contencion.expira_en = ahora + self.ttl
        self._marcar_contenida(contencion.alerta_id)
        self._auditar(self.usuario, "aprobar", "contenciones", contencion_id, {"ip": contencion.ip})
        self._auditar("sensor-simulado", "aplicar", "contenciones", contencion_id,
                      {"switch": contencion.switch, "comandos": contencion.comandos})
        self.notificar()

    def rechazar(self, contencion_id: int) -> None:
        self._requerir_admin("rechazar contenciones")
        contencion = self.contencion(contencion_id)
        if contencion.estado != "propuesta":
            raise EntradaInvalida("Solo se pueden rechazar contenciones pendientes")
        contencion.estado = "rechazada"
        contencion.cerrada_en = datetime.now()
        self._auditar(self.usuario, "rechazar", "contenciones", contencion_id, {"ip": contencion.ip})
        self.notificar()

    def revertir(self, contencion_id: int) -> None:
        self._requerir_admin("revertir contenciones")
        contencion = self.contencion(contencion_id)
        if contencion.estado != "aplicada":
            raise EntradaInvalida("Solo se puede revertir un host que está en cuarentena")
        self._liberar(contencion, "revertida", self.usuario)
        self.notificar()

    def _liberar(self, contencion: Contencion, estado: str, actor: str) -> None:
        contencion.estado = estado
        contencion.cerrada_en = datetime.now()
        if contencion.alerta_id is not None:
            alerta = self.alerta(contencion.alerta_id)
            if alerta.estado == "contenida":
                alerta.estado = "en_revision"
        self._auditar(actor, estado, "contenciones", contencion.id,
                      {"ip": contencion.ip, "vlan_restaurada": contencion.vlan_origen})

    def tick(self) -> None:
        ahora = datetime.now()
        for contencion in self.contenciones:
            if contencion.estado == "aplicada" and contencion.expira_en and contencion.expira_en <= ahora:
                self._liberar(contencion, "expirada", "sistema")

    # ----------------------------------------------------------- auditoría
    def verificar_auditoria(self) -> list[int]:
        """Ids de los registros cuya cadena de hashes no cuadra."""
        rotos, prev = [], GENESIS
        for entrada in self.auditoria:
            if entrada.hash_prev != prev or entrada.calcular_hash() != entrada.hash:
                rotos.append(entrada.id)
            prev = entrada.hash
        return rotos

    def alterar_registro_demo(self) -> int | None:
        """Simula que alguien edita un registro a escondidas, para demostrar la detección."""
        if len(self.auditoria) < 3:
            return None
        entrada = self.auditoria[len(self.auditoria) // 2]
        entrada.detalle = {**entrada.detalle, "alterado": True}
        self.notificar()
        return entrada.id

    # --------------------------------------------------------- indicadores
    def abiertas_por_severidad(self) -> dict[str, int]:
        conteo = dict.fromkeys(SEVERIDADES, 0)
        for alerta in self.alertas:
            if alerta.estado in ESTADOS_ABIERTOS:
                conteo[alerta.severidad] += 1
        return conteo

    def en_cuarentena(self) -> int:
        return sum(1 for c in self.contenciones if c.estado == "aplicada")

    def pendientes(self) -> int:
        return sum(1 for c in self.contenciones if c.estado == "propuesta")

    def principales_origenes(self, n: int = 6) -> list[tuple[str, int, str]]:
        resumen: dict[str, list] = {}
        for alerta in self.alertas:
            fila = resumen.setdefault(alerta.ip_origen, [0, "info"])
            fila[0] += alerta.conteo
            if SEVERIDADES.index(alerta.severidad) > SEVERIDADES.index(fila[1]):
                fila[1] = alerta.severidad
        orden = sorted(resumen.items(), key=lambda kv: kv[1][0], reverse=True)[:n]
        return [(ip, eventos, sev) for ip, (eventos, sev) in orden]
