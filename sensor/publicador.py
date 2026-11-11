"""Publicación de resultados en PostgreSQL con buffer local cifrado (store-and-forward).

El hilo publicador toma operaciones de una cola y las escribe en lotes. Si la
base de datos no responde, el lote se guarda cifrado (AES-256-GCM) en un SQLite
local y se reenvía en orden cuando vuelve la conexión: el sensor nunca deja de
detectar por un corte de internet.
"""
from __future__ import annotations

import base64
import json
import logging
import queue
import sqlite3
import threading
import time
from pathlib import Path

import psycopg

from comun.cripto import Cifrador
from comun.errores import manejar_error

log = logging.getLogger("chontry.sensor")
VOLATILES = {"heartbeat"}   # no tiene sentido guardarlas para después


class BufferLocal:
    """Cola persistente de lotes pendientes. Sin clave maestra solo vive en memoria."""

    def __init__(self, ruta: Path, cifrador: Cifrador | None):
        self.cifrador = cifrador
        self._memoria: list[list[dict]] = []
        self._bd = None
        if cifrador is not None:
            self._bd = sqlite3.connect(str(ruta), check_same_thread=False)
            self._bd.execute("create table if not exists cola (id integer primary key, nonce blob, datos blob)")
            self._bd.commit()
        else:
            log.warning("Sin clave maestra: el buffer sin conexión vive solo en memoria")

    def guardar(self, lote: list[dict]) -> None:
        if self._bd is None:
            self._memoria.append(lote)
            return
        nonce, datos = self.cifrador.cifrar("buffer", json.dumps(lote).encode())
        self._bd.execute("insert into cola (nonce, datos) values (?, ?)", (nonce, datos))
        self._bd.commit()

    def primero(self) -> tuple[int, list[dict]] | None:
        if self._bd is None:
            return (0, self._memoria[0]) if self._memoria else None
        fila = self._bd.execute("select id, nonce, datos from cola order by id limit 1").fetchone()
        if fila is None:
            return None
        return fila[0], json.loads(self.cifrador.descifrar("buffer", fila[1], fila[2]))

    def quitar(self, ident: int) -> None:
        if self._bd is None:
            self._memoria.pop(0)
            return
        self._bd.execute("delete from cola where id = ?", (ident,))
        self._bd.commit()

    def pendientes(self) -> int:
        if self._bd is None:
            return len(self._memoria)
        return self._bd.execute("select count(*) from cola").fetchone()[0]


# ------------------------------------------------- escritura de operaciones
def _b64(valor: str | None) -> bytes | None:
    return base64.b64decode(valor) if valor else None


def _activo(cur, d):
    cur.execute("""insert into chontry.activos (mac, ip, segmento_id, primera_vez, ultima_vez)
                   values (%(mac)s::macaddr, %(ip)s::inet, %(segmento_id)s, %(visto)s, %(visto)s)
                   on conflict (mac) do update set ip = excluded.ip, ultima_vez = excluded.ultima_vez,
                       segmento_id = coalesce(excluded.segmento_id, chontry.activos.segmento_id)""", d)


def _alerta_crear(cur, d):
    cur.execute("""insert into chontry.alertas (uid, sensor_id, regla_id, severidad, puntaje, ip_origen, mac_origen,
                       activo_origen_id, ip_destino, destinos, puertos_destino, protocolo, resumen, detalle,
                       conteo_eventos, primera_deteccion, ultima_deteccion)
                   select %(uid)s, %(sensor_id)s, r.id, %(severidad)s::chontry.severidad, %(puntaje)s,
                          %(ip)s::inet, %(mac)s::macaddr,
                          (select id from chontry.activos where mac = %(mac)s::macaddr),
                          %(ip_destino)s::inet, %(destinos)s::inet[], %(puertos)s::int[], %(protocolo)s,
                          %(resumen)s, %(detalle)s::jsonb, %(conteo)s, %(primera)s, %(ultima)s
                   from chontry.reglas_deteccion r where r.codigo = %(codigo)s
                   on conflict (uid) do nothing""", {**d, "detalle": json.dumps(d["detalle"])})


def _alerta_actualizar(cur, d):
    cur.execute("""update chontry.alertas set conteo_eventos = %(conteo)s, ultima_deteccion = %(ultima)s,
                          puntaje = %(puntaje)s, puertos_destino = %(puertos)s::int[], destinos = %(destinos)s::inet[]
                   where uid = %(uid)s""", d)


def _evidencia(cur, d):
    cur.execute("""insert into chontry.evidencias (alerta_id, tipo, contenido_cifrado, nonce, id_clave,
                                                   sha256_claro, tamano_bytes)
                   select id, %s, %s, %s, %s, %s, %s from chontry.alertas where uid = %s""",
                (d["tipo"], _b64(d["contenido"]), _b64(d["nonce"]), d["id_clave"], _b64(d["sha256"]),
                 d["tamano"], d["alerta_uid"]))


def _contencion_crear(cur, d):
    cur.execute("""insert into chontry.contenciones (uid, alerta_id, activo_id, switch_id, puerto_switch, vlan_origen,
                       vlan_destino, modo, estado, motivo, aplicada_en, expira_en, salida_comando, error)
                   select %(uid)s, (select id from chontry.alertas where uid = %(alerta_uid)s),
                          a.id, %(switch_id)s, %(puerto)s, %(vlan_origen)s, %(vlan_destino)s,
                          %(modo)s::chontry.modo_contencion, %(estado)s::chontry.estado_contencion, %(motivo)s,
                          %(aplicada_en)s, %(expira_en)s, %(salida)s, %(error)s
                   from chontry.activos a where a.mac = %(mac)s::macaddr
                   on conflict (uid) do nothing""", d)


def _contencion_estado(cur, d):
    cur.execute("""update chontry.contenciones set estado = %(estado)s::chontry.estado_contencion,
                          aplicada_en = coalesce(%(aplicada_en)s, aplicada_en),
                          revertida_en = coalesce(%(revertida_en)s, revertida_en),
                          salida_comando = coalesce(%(salida)s, salida_comando), error = %(error)s
                   where uid = %(uid)s""", {"aplicada_en": None, "revertida_en": None, "salida": None, "error": None, **d})


def _metrica(cur, d):
    cur.execute("""insert into chontry.metricas_sensor (sensor_id, ts, paquetes_por_seg, bits_por_seg,
                                                        paquetes_descartados, hosts_activos)
                   values (%(sensor_id)s, %(ts)s, %(pps)s, %(bps)s, %(descartados)s, %(hosts)s)
                   on conflict do nothing""", d)


def _heartbeat(cur, d):
    cur.execute("""update chontry.sensores set estado = %(estado)s::chontry.estado_sensor,
                          ultimo_heartbeat = now(), version = %(version)s where id = %(sensor_id)s""", d)


def _auditar(cur, d):
    cur.execute("""insert into chontry.auditoria (actor_tipo, actor_id, accion, entidad, entidad_id, detalle)
                   values ('sensor', %(actor)s, %(accion)s, %(entidad)s, %(entidad_id)s, %(detalle)s::jsonb)""",
                {**d, "detalle": json.dumps(d["detalle"])})


OPERACIONES = {
    "activo": _activo, "alerta_crear": _alerta_crear, "alerta_actualizar": _alerta_actualizar,
    "evidencia": _evidencia, "contencion_crear": _contencion_crear, "contencion_estado": _contencion_estado,
    "metrica": _metrica, "heartbeat": _heartbeat, "auditar": _auditar,
}


class Publicador(threading.Thread):
    def __init__(self, fabrica_conexion, buffer: BufferLocal):
        super().__init__(name="publicador", daemon=True)
        self._fabrica = fabrica_conexion
        self.buffer = buffer
        self._cola: queue.Queue = queue.Queue()
        self._detener = threading.Event()
        self._conexion = None
        self._reintento = 0.0
        self.en_linea = False
        self.escritas = 0
        self.descartadas = 0

    def enviar(self, operacion: str, /, **datos) -> None:
        self._cola.put({"tipo": operacion, "datos": datos})

    def detener(self, esperar: float = 30) -> None:
        """Termina después de vaciar la cola (o al agotar la espera)."""
        self._detener.set()
        self.join(esperar)

    def vacia(self) -> bool:
        return self._cola.empty()

    # -------------------------------------------------------------- hilo
    def run(self) -> None:
        while not (self._detener.is_set() and self._cola.empty()):
            lote = self._recoger()
            if not self._asegurar_conexion():
                if lote:
                    self._a_buffer(lote)
                continue
            if not self._vaciar_buffer():
                if lote:
                    self._a_buffer(lote)
                continue
            if lote:
                self._escribir_o_guardar(lote)
        if self._conexion is not None:
            self._conexion.close()

    def _recoger(self) -> list[dict]:
        lote = []
        try:
            lote.append(self._cola.get(timeout=0.5))
            while len(lote) < 200:
                lote.append(self._cola.get_nowait())
        except queue.Empty:
            pass
        return lote

    def _asegurar_conexion(self) -> bool:
        if self._conexion is not None and not self._conexion.closed:
            return True
        if time.monotonic() < self._reintento:
            return False
        try:
            self._conexion = self._fabrica()
            if not self.en_linea:
                log.info("Conexión con la base de datos establecida")
            self.en_linea = True
            return True
        except Exception as exc:  # noqa: BLE001 - sin conexión: se trabaja con el buffer
            self._sin_conexion(exc)
            return False

    def _sin_conexion(self, exc: Exception) -> None:
        if self.en_linea or self._reintento == 0.0:
            log.warning("Base de datos no disponible (%s): se guarda en el buffer local", type(exc).__name__)
        self.en_linea = False
        self._conexion = None
        self._reintento = time.monotonic() + 10

    def _a_buffer(self, lote: list[dict]) -> None:
        persistentes = [op for op in lote if op["tipo"] not in VOLATILES]
        if persistentes:
            self.buffer.guardar(persistentes)

    def _vaciar_buffer(self) -> bool:
        while (pendiente := self.buffer.primero()) is not None:
            ident, lote = pendiente
            if not self._escribir(lote):
                return False
            self.buffer.quitar(ident)
            log.info("Lote del buffer sincronizado (%d operaciones)", len(lote))
        return True

    def _escribir_o_guardar(self, lote: list[dict]) -> None:
        if not self._escribir(lote):
            self._a_buffer(lote)

    def _escribir(self, lote: list[dict]) -> bool:
        """True si el lote quedó resuelto (escrito o descartado por inválido); False si se perdió la conexión."""
        try:
            with self._conexion.transaction(), self._conexion.cursor() as cur:
                for op in lote:
                    OPERACIONES[op["tipo"]](cur, op["datos"])
            self.escritas += len(lote)
            return True
        except (psycopg.OperationalError, psycopg.InterfaceError) as exc:
            self._sin_conexion(exc)
            return False
        except psycopg.Error:
            # Un dato inválido no debe bloquear la cola: se reintenta una por una y se descarta la que falle
            return self._escribir_una_por_una(lote)

    def _escribir_una_por_una(self, lote: list[dict]) -> bool:
        for op in lote:
            try:
                with self._conexion.transaction(), self._conexion.cursor() as cur:
                    OPERACIONES[op["tipo"]](cur, op["datos"])
                self.escritas += 1
            except (psycopg.OperationalError, psycopg.InterfaceError) as exc:
                self._sin_conexion(exc)
                return False
            except psycopg.Error as exc:
                self.descartadas += 1
                manejar_error(exc, f"operación {op['tipo']} descartada")
        return True
