"""Backend real de la consola: estado leído de PostgreSQL y acciones que escriben en él.

Expone la misma interfaz que consola.estado.Estado (modo demostración), así que
las vistas funcionan igual con los dos. Las lecturas se hacen en un hilo aparte
cada pocos segundos para no congelar la interfaz; las acciones se ejecutan en
transacciones y las autoriza la propia base de datos (roles + RLS + triggers).
"""
from __future__ import annotations

import csv
import hashlib
import html
import io
import ipaddress
import json
import logging
import re
from collections import deque
from datetime import datetime, timedelta, timezone

import psycopg
from psycopg import errors
from PySide6.QtCore import QObject, QThread, Signal

from comun.cripto import Cifrador, ClaveNoDisponible
from comun.db import conectar
from comun.errores import manejar_error
from comun.validacion import (EntradaInvalida, comandos_cuarentena, validar_interfaz_switch, validar_ip,
                              validar_vlan)
from consola.estado import (CONTENCION_ACTIVA, ESTADOS_ABIERTOS, ESTADOS_ALERTA, SEVERIDADES, Alerta, Contencion,
                            EntradaAuditoria, PermisoDenegado, Regla)

log = logging.getLogger("chontry")
_MAC = re.compile(r"[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}")
INTERVALO_MS = 4000


# ------------------------------------------------------------------ lectura
def _leer_todo(conexion: psycopg.Connection, sesion_id: str | None) -> dict:
    """Instantánea de todo lo que muestra la consola (se ejecuta en el hilo de refresco)."""
    datos: dict = {}
    with conexion.cursor() as cur:
        cur.execute("""select codigo, nombre, categoria, severidad_base::text, accion::text, coalesce(mitre_tecnica,''),
                              parametros, habilitada, id from chontry.reglas_deteccion order by codigo""")
        datos["reglas"] = {f[0]: (Regla(*f[:8]), f[8]) for f in cur.fetchall()}
        cur.execute("select clave, valor from chontry.configuracion")
        datos["config"] = dict(cur.fetchall())
        cur.execute("""select a.id, r.codigo, a.severidad::text, a.puntaje, host(a.ip_origen), coalesce(a.mac_origen::text,'—'),
                              a.primera_deteccion, a.ultima_deteccion, coalesce(array(select host(d) from unnest(a.destinos) d), '{}'),
                              coalesce(a.puertos_destino, '{}'), a.conteo_eventos, a.estado::text, a.uid::text, a.resumen,
                              host(a.ip_destino)
                       from chontry.alertas a join chontry.reglas_deteccion r on r.id = a.regla_id
                       order by a.id desc limit 500""")
        datos["alertas"] = cur.fetchall()
        cur.execute("""select c.id, c.alerta_id, host(ac.ip), ac.mac::text, c.puerto_switch, c.modo::text, c.estado::text,
                              c.motivo, coalesce(us.usuario, 'sensor'), c.creado_en, s.nombre, c.vlan_origen, c.vlan_destino,
                              ua.usuario, c.aplicada_en, c.expira_en, c.revertida_en, c.salida_comando, c.error, s.fabricante
                       from chontry.contenciones c
                       join chontry.activos ac on ac.id = c.activo_id
                       join chontry.switches s on s.id = c.switch_id
                       left join chontry.usuarios us on us.id = c.solicitado_por
                       left join chontry.usuarios ua on ua.id = c.aprobado_por
                       order by c.id desc limit 300""")
        datos["contenciones"] = cur.fetchall()
        cur.execute("""select id, ts, actor_tipo::text, actor_id, accion, entidad, coalesce(entidad_id,''), detalle,
                              hash_prev, hash from chontry.auditoria order by id desc limit 300""")
        datos["auditoria"] = cur.fetchall()
        cur.execute("""select s.id::text, s.nombre, s.estado::text, s.ultimo_heartbeat, s.version,
                              extract(epoch from now() - s.ultimo_heartbeat)
                       from chontry.sensores s order by s.nombre""")
        datos["sensores"] = cur.fetchall()
        cur.execute("""select paquetes_por_seg from (select ts, paquetes_por_seg from chontry.metricas_sensor
                       order by ts desc limit 120) m order by ts""")
        datos["pps"] = [f[0] for f in cur.fetchall()]
        cur.execute("""select a.id, host(a.ip), a.mac::text, a.hostname, sg.nombre, sw.nombre, a.puerto_switch,
                              a.vlan_actual, a.criticidad, a.protegido, a.notas, a.ultima_vez, a.switch_id, sg.vlan_id
                       from chontry.activos a
                       left join chontry.segmentos_red sg on sg.id = a.segmento_id
                       left join chontry.switches sw on sw.id = a.switch_id
                       order by a.protegido desc, a.ultima_vez desc limit 1000""")
        datos["activos"] = cur.fetchall()
        cur.execute("""select l.id, case when l.red is null then null else host(l.red) || '/' || masklen(l.red) end,
                              l.mac::text, coalesce(r.codigo, 'Todas'), l.motivo, u.usuario, l.creado_en, l.expira_en
                       from chontry.lista_blanca l
                       left join chontry.reglas_deteccion r on r.id = l.regla_id
                       left join chontry.usuarios u on u.id = l.creado_por
                       order by l.id desc""")
        datos["lista_blanca"] = cur.fetchall()
        cur.execute("""select id, usuario, nombre_completo, rol::text, activo, bloqueado_hasta, debe_cambiar_clave,
                              ultimo_login, rol_bd from chontry.usuarios order by usuario""")
        datos["usuarios"] = cur.fetchall()
        cur.execute("""select r.id, r.tipo, r.formato, r.desde, r.hasta, u.usuario, r.creado_en, encode(r.sha256, 'hex')
                       from chontry.reportes r join chontry.usuarios u on u.id = r.generado_por
                       order by r.id desc limit 100""")
        datos["reportes"] = cur.fetchall()
        cur.execute("select id, nombre, puerto_span, vlan_cuarentena from chontry.switches order by nombre")
        datos["switches"] = cur.fetchall()
        datos["sesion_valida"] = True
        if sesion_id:
            cur.execute("select revocada_en is null and expira_en > now() from chontry.sesiones where id = %s",
                        (sesion_id,))
            fila = cur.fetchone()
            datos["sesion_valida"] = bool(fila and fila[0])
    return datos


class Refrescador(QThread):
    datos = Signal(object)
    fallo = Signal(str)

    def __init__(self, url: str, sesion_id: str | None):
        super().__init__()
        self._url = url
        self._sesion_id = sesion_id
        self._activo = True
        self._ahora = False

    def solicitar(self) -> None:
        self._ahora = True

    def detener(self) -> None:
        self._activo = False
        self.wait(6000)

    def run(self) -> None:
        conexion = None
        while self._activo:
            try:
                if conexion is None or conexion.closed:
                    conexion = conectar(self._url, aplicacion="chontry-consola-lectura")
                self.datos.emit(_leer_todo(conexion, self._sesion_id))
            except psycopg.Error as exc:
                conexion = None
                self.fallo.emit(manejar_error(exc, "refrescar datos de la consola"))
            for _ in range(INTERVALO_MS // 100):
                if not self._activo or self._ahora:
                    break
                self.msleep(100)
            self._ahora = False
        if conexion is not None:
            conexion.close()


# -------------------------------------------------------------- estado real
class EstadoNeon(QObject):
    cambio = Signal()
    sesion_terminada = Signal(str)
    es_demo = False

    def __init__(self, conexion: psycopg.Connection, url: str, cuenta: dict, sesion_id: str | None,
                 cifrador: Cifrador | None):
        super().__init__()
        self._conexion = conexion
        self.usuario = cuenta["usuario"]
        self.usuario_id = cuenta["id"]
        self.rol = cuenta["rol"]
        self.sesion_id = sesion_id
        self.cifrador = cifrador
        host = url.split("@")[-1].split("/")[0].split(":")[0]
        self.origen_catalogo = "Neon" if host.endswith("neon.tech") else f"PostgreSQL ({host})"
        self.tls_verificado = "sslmode=verify-full" in url
        self.reglas: dict[str, Regla] = {}
        self._id_regla: dict[str, int] = {}
        self.config: dict = {}
        self.ttl = timedelta(minutes=60)
        self.protegidos: dict[str, str] = {}
        self.alertas: list[Alerta] = []
        self.contenciones: list[Contencion] = []
        self.auditoria: list[EntradaAuditoria] = []
        self.pps: deque[int] = deque(maxlen=120)
        self.sensores: list[tuple] = []
        self.activos: list[tuple] = []
        self.lista_blanca: list[tuple] = []
        self.usuarios: list[tuple] = []
        self.reportes: list[tuple] = []
        self.switches: list[tuple] = []
        self.ultimo_error: str | None = None
        self._cargado = False
        self._refrescador = Refrescador(url, sesion_id)
        self._refrescador.datos.connect(self._aplicar)
        self._refrescador.fallo.connect(self._al_fallar)
        # Primera carga síncrona: la ventana abre ya con datos
        self._aplicar(_leer_todo(conexion, sesion_id))
        self._refrescador.start()

    # ------------------------------------------------------------ roles
    @property
    def es_admin(self) -> bool:
        return self.rol == "admin"

    @property
    def puede_operar(self) -> bool:
        return self.rol in ("admin", "analista")

    def notificar(self) -> None:
        self.cambio.emit()

    def refrescar(self) -> None:
        self._refrescador.solicitar()

    def cerrar(self, motivo: str = "cierre_sesion") -> None:
        self._refrescador.detener()
        try:
            with self._conexion.transaction(), self._conexion.cursor() as cur:
                if self.sesion_id:
                    cur.execute("update chontry.sesiones set revocada_en = now() where id = %s and revocada_en is null",
                                (self.sesion_id,))
                cur.execute("""insert into chontry.auditoria (actor_tipo, actor_id, accion, entidad, entidad_id, detalle)
                               values ('usuario', %s, %s, 'sesiones', %s, '{}'::jsonb)""",
                            (self.usuario, motivo, self.sesion_id or "-"))
        except psycopg.Error as exc:
            manejar_error(exc, "cerrar sesión")
        self._conexion.close()

    # ---------------------------------------------------------- aplicar
    def _al_fallar(self, mensaje: str) -> None:
        self.ultimo_error = mensaje
        self.cambio.emit()

    def _aplicar(self, d: dict) -> None:
        self.ultimo_error = None
        self.reglas = {c: r for c, (r, _) in d["reglas"].items()}
        self._id_regla = {c: i for c, (_, i) in d["reglas"].items()}
        self.config = d["config"]
        self.ttl = timedelta(minutes=int(self.config.get("contencion.ttl_minutos", 60)))
        base = Regla("?", "Regla desconocida", "-", "info", "alertar", "", {})
        self.alertas = [Alerta(f[0], self.reglas.get(f[1], base), f[2], f[3], f[4], f[5], f[6], f[7], set(f[8]),
                               set(f[9]), f[10], f[11], uid=f[12], texto=f[13]) for f in d["alertas"]]
        self.alertas.reverse()
        self.contenciones = []
        for f in d["contenciones"]:
            try:
                comandos = comandos_cuarentena(f[19], f[4], f[12])
            except EntradaInvalida:
                comandos = ["(sin plantilla para este fabricante)"]
            self.contenciones.append(Contencion(
                f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7], f[8], f[9], comandos, switch=f[10],
                vlan_origen=f[11], vlan_destino=f[12], aprobado_por=f[13], aplicada_en=f[14], expira_en=f[15],
                cerrada_en=f[16], salida=f[17], error=f[18]))
        self.contenciones.reverse()
        self.auditoria = [EntradaAuditoria(f[0], f[1], f"{f[3]}" if f[2] != "sistema" else f"{f[3]} (sistema)",
                                           f[4], f[5], f[6], f[7], bytes(f[8]), bytes(f[9])) for f in d["auditoria"]]
        self.auditoria.reverse()
        self.sensores = d["sensores"]
        self.pps = deque(d["pps"], maxlen=120)
        self.activos = d["activos"]
        self.protegidos = {f[1]: f[3] or "activo protegido" for f in self.activos if f[9] and f[1]}
        self.lista_blanca = d["lista_blanca"]
        self.usuarios = d["usuarios"]
        self.reportes = d["reportes"]
        self.switches = d["switches"]
        self._cargado = True
        self.cambio.emit()
        if not d["sesion_valida"]:
            self.sesion_terminada.emit("Su sesión fue cerrada por un administrador o venció.")

    # ------------------------------------------------------- escritura
    def _ejecutar(self, sentencia: str, parametros=(), esperar_filas: bool = True) -> int:
        try:
            with self._conexion.transaction(), self._conexion.cursor() as cur:
                cur.execute("select set_config('chontry.actor_id', %s, true)", (str(self.usuario_id),))
                cur.execute(sentencia, parametros)
                filas = cur.rowcount
        except errors.InsufficientPrivilege as exc:
            manejar_error(exc, "acción rechazada por la base de datos")
            raise PermisoDenegado("La base de datos rechazó la acción: su rol no tiene permiso.") from None
        except (errors.CheckViolation, errors.UniqueViolation, errors.ForeignKeyViolation,
                errors.InvalidTextRepresentation, errors.RaiseException) as exc:
            manejar_error(exc, "acción con datos inválidos")
            raise EntradaInvalida(_mensaje_restriccion(exc)) from None
        if esperar_filas and filas == 0:
            raise EntradaInvalida("El registro ya no existe o cambió; se actualizará la vista.")
        self.refrescar()
        return filas

    def cambiar_estado_alerta(self, alerta_id: int, estado: str) -> None:
        if estado not in ESTADOS_ALERTA:
            raise EntradaInvalida("Estado de alerta inválido")
        self._ejecutar("update chontry.alertas set estado = %s::chontry.estado_alerta where id = %s",
                       (estado, alerta_id))

    def proponer_manual(self, ip: str, puerto: str, vlan, motivo: str) -> None:
        ip = str(validar_ip(ip.strip()))
        vlan = validar_vlan(vlan)
        motivo = motivo.strip()
        if not 10 <= len(motivo) <= 300:
            raise EntradaInvalida("El motivo debe tener entre 10 y 300 caracteres")
        activo = next((a for a in self.activos if a[1] == ip), None)
        if activo is None:
            raise EntradaInvalida("Ese host no está en el inventario de activos (aún no lo ha visto el sensor)")
        if activo[9]:
            raise EntradaInvalida(f"{ip} es un activo protegido y no se puede aislar")
        puerto = validar_interfaz_switch((puerto or activo[6] or "").strip())
        switch_id = activo[12] or (self.switches[0][0] if len(self.switches) == 1 else None)
        if switch_id is None:
            raise EntradaInvalida("No se sabe en qué switch está el host: asígnelo en Activos")
        vlan_origen = activo[7] or activo[13]
        if vlan_origen is None:
            raise EntradaInvalida("No se conoce la VLAN actual del host: asígnela en Activos")
        if vlan == vlan_origen:
            raise EntradaInvalida("La VLAN destino no puede ser la misma VLAN de origen")
        self._ejecutar("""insert into chontry.contenciones (activo_id, switch_id, puerto_switch, vlan_origen,
                                                            vlan_destino, modo, estado, motivo, solicitado_por)
                          values (%s, %s, %s, %s, %s, 'manual', 'propuesta', %s, %s)""",
                       (activo[0], switch_id, puerto, vlan_origen, vlan, motivo, self.usuario_id))

    def aprobar(self, contencion_id: int) -> None:
        self._exigir_admin("aprobar contenciones")
        self._ejecutar("""update chontry.contenciones set estado = 'aprobada', aprobado_por = %s
                          where id = %s and estado = 'propuesta'""", (self.usuario_id, contencion_id))

    def rechazar(self, contencion_id: int) -> None:
        self._exigir_admin("rechazar contenciones")
        self._ejecutar("""update chontry.contenciones set estado = 'rechazada', aprobado_por = %s
                          where id = %s and estado = 'propuesta'""", (self.usuario_id, contencion_id))

    def revertir(self, contencion_id: int) -> None:
        self._exigir_admin("liberar hosts")
        self._ejecutar("""update chontry.contenciones set estado = 'por_revertir', revertida_por = %s
                          where id = %s and estado = 'aplicada'""", (self.usuario_id, contencion_id))

    def _exigir_admin(self, accion: str) -> None:
        # Comodidad de la interfaz: la BD lo rechazaría igual (rol chontry_admin)
        if not self.es_admin:
            raise PermisoDenegado(f"Solo un administrador puede {accion}.")

    # ---------------------------------------------------- activos y reglas
    def actualizar_activo(self, activo_id: int, hostname: str, notas: str, criticidad: int | None = None,
                          protegido: bool | None = None, puerto: str | None = None, vlan: int | None = None) -> None:
        hostname, notas = hostname.strip()[:120], notas.strip()[:500]
        if hostname and not re.fullmatch(r"[A-Za-z0-9._-]{1,63}", hostname):
            raise EntradaInvalida("Nombre de host inválido (letras, números, punto, guion)")
        if not self.es_admin:
            self._ejecutar("update chontry.activos set hostname = nullif(%s, ''), notas = nullif(%s, '') where id = %s",
                           (hostname, notas, activo_id))
            return
        if puerto:
            validar_interfaz_switch(puerto)
        if vlan is not None:
            validar_vlan(vlan)
        if criticidad is not None and not 1 <= criticidad <= 5:
            raise EntradaInvalida("La criticidad va de 1 a 5")
        self._ejecutar("""update chontry.activos set hostname = nullif(%s, ''), notas = nullif(%s, ''),
                                 criticidad = coalesce(%s, criticidad), protegido = coalesce(%s, protegido),
                                 puerto_switch = coalesce(nullif(%s, ''), puerto_switch),
                                 vlan_actual = coalesce(%s, vlan_actual)
                          where id = %s""", (hostname, notas, criticidad, protegido, puerto or "", vlan, activo_id))

    def habilitar_regla(self, codigo: str, habilitada: bool) -> None:
        self._exigir_admin("cambiar reglas")
        self._ejecutar("update chontry.reglas_deteccion set habilitada = %s, version = version + 1 where codigo = %s",
                       (habilitada, codigo))

    def agregar_lista_blanca(self, valor: str, codigo: str | None, motivo: str, dias: int) -> None:
        self._exigir_admin("modificar la lista blanca")
        valor, motivo = valor.strip(), motivo.strip()
        red = mac = None
        if _MAC.fullmatch(valor):
            mac = valor.lower()
        else:
            try:
                red = str(ipaddress.ip_network(valor, strict=False))
            except ValueError:
                raise EntradaInvalida("Escriba una IP, una red (10.10.20.0/24) o una MAC (aa:bb:cc:dd:ee:ff)") from None
        if not 10 <= len(motivo) <= 300:
            raise EntradaInvalida("Justifique la excepción (entre 10 y 300 caracteres)")
        if not 0 <= dias <= 365:
            raise EntradaInvalida("La vigencia va de 0 (sin vencimiento) a 365 días")
        self._ejecutar("""insert into chontry.lista_blanca (red, mac, regla_id, motivo, creado_por, expira_en)
                          values (%s::cidr, %s::macaddr, %s, %s, %s,
                                  case when %s > 0 then now() + make_interval(days => %s) end)""",
                       (red, mac, self._id_regla.get(codigo) if codigo else None, motivo, self.usuario_id, dias, dias))

    def quitar_lista_blanca(self, ident: int) -> None:
        self._exigir_admin("modificar la lista blanca")
        self._ejecutar("delete from chontry.lista_blanca where id = %s", (ident,))

    # ------------------------------------------------------------ usuarios
    def administrar_usuario(self, usuario_id, accion: str) -> None:
        self._exigir_admin("administrar usuarios")
        if str(usuario_id) == str(self.usuario_id) and accion in ("desactivar", "cerrar_sesiones"):
            raise EntradaInvalida("No puede desactivar ni cerrar las sesiones de su propia cuenta")
        sentencias = {
            "activar": "update chontry.usuarios set activo = true where id = %s",
            "desactivar": "update chontry.usuarios set activo = false where id = %s",
            "forzar_cambio": "update chontry.usuarios set debe_cambiar_clave = true where id = %s",
            "reiniciar_mfa": "update chontry.usuarios set mfa_secreto_cifrado = null where id = %s",
            "desbloquear": "update chontry.usuarios set intentos_fallidos = 0, bloqueado_hasta = null where id = %s",
            "cerrar_sesiones": "update chontry.sesiones set revocada_en = now() where usuario_id = %s and revocada_en is null",
        }
        if accion not in sentencias:
            raise EntradaInvalida("Acción no válida")
        self._ejecutar(sentencias[accion], (usuario_id,), esperar_filas=accion != "cerrar_sesiones")

    # ---------------------------------------------------------- evidencias
    def evidencias(self, alerta: Alerta) -> list[tuple[str, bytes]]:
        """Descifra las evidencias de una alerta y comprueba su SHA-256 (cadena de custodia)."""
        if self.cifrador is None:
            raise EntradaInvalida("Este equipo no tiene la clave maestra: no puede abrir evidencias cifradas")
        with self._conexion.cursor() as cur:
            cur.execute("""select tipo, contenido_cifrado, nonce, sha256_claro from chontry.evidencias
                           where alerta_id = %s order by id""", (alerta.id,))
            filas = cur.fetchall()
        resultado = []
        for tipo, cifrado, nonce, resumen in filas:
            try:
                claro = self.cifrador.descifrar("evidencias", bytes(nonce), bytes(cifrado), (alerta.uid or "").encode())
            except Exception:   # noqa: BLE001 - clave distinta o contenido alterado
                raise EntradaInvalida("No se pudo descifrar la evidencia (clave distinta o contenido alterado)") from None
            if hashlib.sha256(claro).digest() != bytes(resumen):
                raise EntradaInvalida("La evidencia no coincide con su SHA-256: fue alterada")
            resultado.append((tipo, claro))
        self._ejecutar("""insert into chontry.auditoria (actor_tipo, actor_id, accion, entidad, entidad_id, detalle)
                          values ('usuario', %s, 'exportar_evidencia', 'alertas', %s, '{}'::jsonb)""",
                       (self.usuario, str(alerta.id)))
        return resultado

    # ------------------------------------------------------------ reportes
    def generar_reporte(self, tipo: str, desde: datetime, hasta: datetime, formato: str) -> tuple[bytes, str]:
        """Devuelve (contenido, sha256 hex) y lo registra en chontry.reportes con el ancla de la auditoría."""
        if hasta <= desde:
            raise EntradaInvalida("La fecha final debe ser posterior a la inicial")
        consultas = {
            "alertas": ("""select a.id, a.primera_deteccion, r.codigo, a.severidad, host(a.ip_origen), a.mac_origen,
                                  a.conteo_eventos, a.puntaje, a.estado, a.resumen
                           from chontry.alertas a join chontry.reglas_deteccion r on r.id = a.regla_id
                           where a.primera_deteccion between %s and %s order by a.id""",
                        ["#", "Detectada", "Regla", "Severidad", "Origen", "MAC", "Eventos", "Puntaje", "Estado", "Resumen"]),
            "contenciones": ("""select c.id, c.creado_en, host(ac.ip), s.nombre, c.puerto_switch, c.vlan_origen,
                                       c.vlan_destino, c.modo, c.estado, c.motivo, c.aplicada_en, c.revertida_en
                                from chontry.contenciones c join chontry.activos ac on ac.id = c.activo_id
                                join chontry.switches s on s.id = c.switch_id
                                where c.creado_en between %s and %s order by c.id""",
                             ["#", "Creada", "Host", "Switch", "Puerto", "VLAN origen", "VLAN destino", "Modo",
                              "Estado", "Motivo", "Aplicada", "Liberada"]),
            "auditoria": ("""select id, ts, actor_tipo, actor_id, accion, entidad, entidad_id, encode(hash, 'hex')
                             from chontry.auditoria where ts between %s and %s order by id""",
                          ["#", "Fecha", "Tipo de actor", "Actor", "Acción", "Entidad", "ID", "Hash SHA-256"]),
        }
        if tipo not in consultas or formato not in ("csv", "html"):
            raise EntradaInvalida("Tipo o formato de reporte inválido")
        consulta, columnas = consultas[tipo]
        with self._conexion.cursor() as cur:
            cur.execute(consulta, (desde, hasta))
            filas = cur.fetchall()
            cur.execute("select id, encode(hash, 'hex') from chontry.auditoria order by id desc limit 1")
            ancla = cur.fetchone() or (0, "-")
        meta = {"Reporte": tipo, "Desde": desde.isoformat(timespec="minutes"), "Hasta": hasta.isoformat(timespec="minutes"),
                "Generado por": self.usuario, "Generado": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "Registros": str(len(filas)), "Ancla de auditoría": f"#{ancla[0]} {ancla[1]}"}
        contenido = (_csv if formato == "csv" else _html)(meta, columnas, filas)
        resumen = hashlib.sha256(contenido).hexdigest()
        self._ejecutar("""insert into chontry.reportes (tipo, desde, hasta, formato, sha256, generado_por)
                          values (%s, %s, %s, %s, decode(%s, 'hex'), %s)""",
                       (tipo, desde, hasta, formato, resumen, self.usuario_id))
        return contenido, resumen

    # ---------------------------------------------------------- auditoría
    def verificar_auditoria(self) -> list[int]:
        with self._conexion.cursor() as cur:
            cur.execute("select id from chontry.verificar_auditoria()")
            return [f[0] for f in cur.fetchall()]

    # -------------------------------------------------------- indicadores
    def alerta(self, alerta_id: int) -> Alerta:
        return next(a for a in self.alertas if a.id == alerta_id)

    def contencion(self, contencion_id: int) -> Contencion:
        return next(c for c in self.contenciones if c.id == contencion_id)

    def abiertas_por_severidad(self) -> dict[str, int]:
        conteo = dict.fromkeys(SEVERIDADES, 0)
        for alerta in self.alertas:
            if alerta.estado in ESTADOS_ABIERTOS:
                conteo[alerta.severidad] += 1
        return conteo

    def en_cuarentena(self) -> int:
        return sum(1 for c in self.contenciones if c.estado in ("aplicada", "por_revertir"))

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

    def contenciones_activas(self) -> int:
        return sum(1 for c in self.contenciones if c.estado in CONTENCION_ACTIVA)


# ------------------------------------------------------------ utilidades
def _mensaje_restriccion(exc: psycopg.Error) -> str:
    texto = (exc.diag.message_primary or "").lower()
    if "span" in texto:
        return "Ese puerto es el puerto SPAN del sensor: aislarlo dejaría ciego al IDS."
    if isinstance(exc, errors.UniqueViolation):
        return "Ya existe un registro igual (por ejemplo, una contención activa para ese host)."
    return "Los datos no cumplen las reglas de validación de la base de datos."


def _celda_csv(valor) -> str:
    """Evita la inyección de fórmulas al abrir el CSV en Excel (ASVS V5)."""
    texto = "" if valor is None else (valor.isoformat(timespec="seconds") if isinstance(valor, datetime) else str(valor))
    return "'" + texto if texto[:1] in ("=", "+", "-", "@", "\t", "\r") else texto


def _csv(meta: dict, columnas: list[str], filas: list) -> bytes:
    salida = io.StringIO()
    escritor = csv.writer(salida)
    for clave, valor in meta.items():
        escritor.writerow([f"# {clave}", _celda_csv(valor)])
    escritor.writerow(columnas)
    for fila in filas:
        escritor.writerow([_celda_csv(v) for v in fila])
    return ("﻿" + salida.getvalue()).encode("utf-8")


def _html(meta: dict, columnas: list[str], filas: list) -> bytes:
    def celda(valor):
        if isinstance(valor, datetime):
            valor = valor.isoformat(timespec="seconds")
        return html.escape("" if valor is None else str(valor))
    cabecera = "".join(f"<th>{html.escape(c)}</th>" for c in columnas)
    cuerpo = "".join("<tr>" + "".join(f"<td>{celda(v)}</td>" for v in fila) + "</tr>" for fila in filas)
    datos = "".join(f"<tr><th>{html.escape(k)}</th><td>{html.escape(v)}</td></tr>" for k, v in meta.items())
    return f"""<!DOCTYPE html><html lang="es"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>ChonTry · Reporte de {html.escape(meta['Reporte'])}</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;color:#1b2a35;margin:32px}}h1{{color:#12304a}}
h1 span{{color:#12805c}}table{{border-collapse:collapse;width:100%;font-size:13px;margin:14px 0}}
th,td{{border:1px solid #dbe4df;padding:6px 8px;text-align:left}}thead th{{background:#12304a;color:#fff}}
.meta th{{background:#e3f3ec;width:200px}}</style></head><body>
<h1>Chon<span>Try</span> · Reporte de {html.escape(meta['Reporte'])}</h1>
<table class="meta">{datos}</table>
<table><thead><tr>{cabecera}</tr></thead><tbody>{cuerpo}</tbody></table>
<p>La integridad de este archivo se verifica con el SHA-256 registrado en la tabla chontry.reportes.</p>
</body></html>""".encode("utf-8")
