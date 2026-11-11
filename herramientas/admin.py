"""Herramienta de administración de ChonTry (la usa el administrador de la BD).

Se conecta con el rol DUEÑO de la base de datos, solo para tareas de instalación:
migraciones, logins, usuarios, sensores y switches. La consola y el sensor
nunca usan ese rol (mínimo privilegio, SSDF PW.9).

    python -m herramientas.admin --ayuda
    python -m herramientas.admin migrar
    python -m herramientas.admin crear-login ct_erick --rol admin
    python -m herramientas.admin crear-usuario erick --nombre "Erick ..." --rol admin --login ct_erick

La URL del dueño se toma de CHONTRY_DB_URL_ADMIN o se pide sin mostrarla.
"""
import argparse
import getpass
import hashlib
import json
import os
import re
import secrets
import sys
from pathlib import Path

import psycopg
from psycopg import sql

from comun import cripto
from comun.config import RAIZ, cargar_env
from comun.db import VARIABLE_ADMIN, conectar
from comun.validacion import (EntradaInvalida, validar_fabricante, validar_filtro_bpf,
                              validar_interfaz_captura, validar_interfaz_switch, validar_ip)

CARPETA_MIGRACIONES = RAIZ / "db"
SEPARADOR = re.compile(r"(?m)^--@@\s*$")
LOGIN = re.compile(r"ct_[a-z0-9_]{3,40}")
USUARIO = re.compile(r"[a-z0-9._-]{3,32}")
GRUPOS = {"sensor": "chontry_sensor", "analista": "chontry_consola",
          "admin": "chontry_admin", "auditor": "chontry_auditor"}


# ------------------------------------------------------------ migraciones
def migraciones_disponibles(carpeta: Path = CARPETA_MIGRACIONES) -> list[Path]:
    return sorted(p for p in carpeta.glob("[0-9][0-9][0-9]_*.sql"))


def sentencias(archivo: Path) -> list[str]:
    texto = archivo.read_text(encoding="utf-8")
    bloques = [b.strip() for b in SEPARADOR.split(texto)]
    return [b for b in bloques if any(l.strip() and not l.strip().startswith("--") for l in b.splitlines())]


def _version(archivo: Path) -> str:
    return archivo.name.split("_", 1)[0]


def _linea_base(cur) -> list[str]:
    """Migraciones aplicadas antes de existir el registro (BD creada a mano el 2026-11-03)."""
    cur.execute("select to_regclass('chontry.alertas') is not null")
    if not cur.fetchone()[0]:
        return []
    pruebas = {
        "001": "select true",
        "002": "select exists (select 1 from information_schema.columns where table_schema='chontry' "
               "and table_name='usuarios' and column_name='rol_bd')",
        "003": "select coalesce(pg_get_constraintdef((select oid from pg_constraint where conname='ck_sensores_bpf')) "
               "like '%length%', false)",
        "004": "select has_function_privilege('chontry_sensor', 'chontry.es_interfaz_switch(text)', 'execute')",
        "005": "select exists (select 1 from pg_enum e join pg_type t on t.oid=e.enumtypid "
               "where t.typname='estado_contencion' and e.enumlabel='por_revertir')",
        "006": "select exists (select 1 from information_schema.columns where table_schema='chontry' "
               "and table_name='alertas' and column_name='uid')",
    }
    aplicadas = []
    for version, consulta in pruebas.items():
        cur.execute(consulta)
        if not cur.fetchone()[0]:
            break
        aplicadas.append(version)
    return aplicadas


def aplicar_migraciones(conexion: psycopg.Connection, salida=print) -> list[str]:
    """Aplica en orden las migraciones pendientes, cada una en su propia transacción."""
    with conexion.cursor() as cur:
        cur.execute("create schema if not exists chontry")
        cur.execute("""create table if not exists chontry.schema_migraciones (
                         version text primary key, archivo text not null, sha256 text not null,
                         aplicada_en timestamptz not null default now())""")
        cur.execute("select version from chontry.schema_migraciones")
        hechas = {fila[0] for fila in cur.fetchall()}
        if not hechas:
            for version in _linea_base(cur):
                archivo = next(p for p in migraciones_disponibles() if _version(p) == version)
                cur.execute("insert into chontry.schema_migraciones (version, archivo, sha256) values (%s, %s, %s)",
                            (version, archivo.name, "linea-base"))
                hechas.add(version)
                salida(f"  {archivo.name}: ya estaba aplicada (línea base)")

    aplicadas = []
    for archivo in migraciones_disponibles():
        version = _version(archivo)
        if version in hechas:
            continue
        resumen = hashlib.sha256(archivo.read_bytes()).hexdigest()
        with conexion.transaction(), conexion.cursor() as cur:
            for sentencia in sentencias(archivo):
                cur.execute(sentencia)
            cur.execute("insert into chontry.schema_migraciones (version, archivo, sha256) values (%s, %s, %s)",
                        (version, archivo.name, resumen))
        aplicadas.append(archivo.name)
        salida(f"  {archivo.name}: aplicada")
    return aplicadas


# ------------------------------------------------------- logins y usuarios
def crear_login(conexion: psycopg.Connection, nombre: str, rol: str, clave: str | None = None) -> str:
    """Crea un login de PostgreSQL miembro del grupo del rol. Devuelve la contraseña (se muestra una vez)."""
    if not LOGIN.fullmatch(nombre):
        raise EntradaInvalida("El login debe ser ct_ seguido de 3 a 40 caracteres a-z, 0-9 o _")
    if rol not in GRUPOS:
        raise EntradaInvalida(f"Rol inválido; use uno de: {', '.join(GRUPOS)}")
    clave = clave or secrets.token_urlsafe(24)
    with conexion.transaction(), conexion.cursor() as cur:
        cur.execute(sql.SQL("create role {} login password {}").format(sql.Identifier(nombre), sql.Literal(clave)))
        cur.execute(sql.SQL("grant {} to {}").format(sql.Identifier(GRUPOS[rol]), sql.Identifier(nombre)))
    return clave


def eliminar_login(conexion: psycopg.Connection, nombre: str) -> None:
    if not LOGIN.fullmatch(nombre):
        raise EntradaInvalida("Login inválido")
    with conexion.transaction(), conexion.cursor() as cur:
        cur.execute(sql.SQL("drop role if exists {}").format(sql.Identifier(nombre)))


def crear_usuario(conexion: psycopg.Connection, usuario: str, nombre: str, rol: str, login: str,
                  email: str | None = None, clave: str | None = None) -> str:
    """Crea la cuenta de la consola enlazada a un login de BD. Devuelve la contraseña temporal."""
    if not USUARIO.fullmatch(usuario):
        raise EntradaInvalida("Usuario inválido: 3 a 32 caracteres a-z, 0-9, punto, guion o guion bajo")
    if rol not in ("admin", "analista", "auditor"):
        raise EntradaInvalida("El rol de la consola debe ser admin, analista o auditor")
    if not LOGIN.fullmatch(login):
        raise EntradaInvalida("Login de BD inválido")
    with conexion.cursor() as cur:
        cur.execute("select exists (select 1 from pg_roles where rolname = %s)", (login,))
        if not cur.fetchone()[0]:
            raise EntradaInvalida(f"El login {login} no existe; créelo primero con crear-login")
        cur.execute("select pg_has_role(%s, %s, 'MEMBER')", (login, GRUPOS[rol]))
        if not cur.fetchone()[0]:
            raise EntradaInvalida(f"El login {login} no pertenece al grupo {GRUPOS[rol]}")
    clave = clave or cripto.generar_clave_temporal()
    with conexion.transaction(), conexion.cursor() as cur:
        cur.execute("""insert into chontry.usuarios (usuario, nombre_completo, email, password_hash, rol, rol_bd,
                                                    debe_cambiar_clave)
                       values (%s, %s, %s, %s, %s, %s, true)""",
                    (usuario, nombre, email, cripto.hashear_clave(clave), rol, login))
    return clave


# --------------------------------------------------- sensores y switches
def registrar_switch(conexion, nombre, ip, fabricante, credencial_ref, huella=None, puerto_span=None,
                     vlan_cuarentena=999, puerto_ssh=22) -> int:
    validar_ip(ip)
    validar_fabricante(fabricante)
    if puerto_span:
        validar_interfaz_switch(puerto_span)
    with conexion.transaction(), conexion.cursor() as cur:
        cur.execute("""insert into chontry.switches (nombre, ip_gestion, fabricante, credencial_ref, huella_ssh_host,
                                                    puerto_span, vlan_cuarentena, puerto_ssh)
                       values (%s, %s, %s, %s, %s, %s, %s, %s) returning id""",
                    (nombre, ip, fabricante, credencial_ref, huella, puerto_span, vlan_cuarentena, puerto_ssh))
        return cur.fetchone()[0]


TIPOS_SEGMENTO = ("gestion", "usuarios", "servidores", "invitados", "cuarentena", "otro")


def registrar_segmento(conexion, nombre: str, red: str, vlan: int, tipo: str) -> int:
    """Registra (o actualiza) un segmento de la red: el sensor lo usa para saber la VLAN de cada equipo."""
    import ipaddress
    try:
        red = str(ipaddress.ip_network(red, strict=False))
    except ValueError:
        raise EntradaInvalida("Red inválida; use el formato 192.168.1.0/24") from None
    if not 1 <= vlan <= 4094:
        raise EntradaInvalida("La VLAN va de 1 a 4094")
    if tipo not in TIPOS_SEGMENTO:
        raise EntradaInvalida(f"Tipo inválido; use uno de: {', '.join(TIPOS_SEGMENTO)}")
    with conexion.transaction(), conexion.cursor() as cur:
        cur.execute("""insert into chontry.segmentos_red (nombre, red, vlan_id, tipo)
                       values (%s, %s, %s, %s::chontry.tipo_segmento)
                       on conflict (red) do update set nombre = excluded.nombre, vlan_id = excluded.vlan_id,
                                                       tipo = excluded.tipo
                       returning id""", (nombre, red, vlan, tipo))
        return cur.fetchone()[0]


def registrar_sensor(conexion, nombre, interfaz, filtro=None, ubicacion=None, switch=None) -> str:
    validar_interfaz_captura(interfaz)
    if filtro:
        validar_filtro_bpf(filtro)
    with conexion.transaction(), conexion.cursor() as cur:
        cur.execute("""insert into chontry.sensores (nombre, interfaz_captura, filtro_bpf, ubicacion, switch_id)
                       values (%s, %s, %s, %s, (select id from chontry.switches where nombre = %s))
                       returning id""", (nombre, interfaz, filtro, ubicacion, switch))
        return str(cur.fetchone()[0])


def configurar(conexion, clave: str, valor) -> None:
    with conexion.transaction(), conexion.cursor() as cur:
        cur.execute("""insert into chontry.configuracion (clave, valor) values (%s, %s::jsonb)
                       on conflict (clave) do update set valor = excluded.valor""", (clave, json.dumps(valor)))


def configurar_regla(conexion, codigo: str, parametros: dict | None = None, habilitada: bool | None = None) -> None:
    with conexion.transaction(), conexion.cursor() as cur:
        cur.execute("""update chontry.reglas_deteccion
                          set parametros = coalesce(%s::jsonb, parametros),
                              habilitada = coalesce(%s, habilitada), version = version + 1
                        where codigo = %s""",
                    (json.dumps(parametros) if parametros is not None else None, habilitada, codigo))
        if cur.rowcount != 1:
            raise EntradaInvalida(f"No existe la regla {codigo}")


def guardar_credencial_switch(referencia: str, usuario: str, clave: str) -> None:
    import keyring
    keyring.set_password("chontry-switch", referencia, json.dumps({"usuario": usuario, "clave": clave}))


def huella_ssh(host: str, puerto: int = 22) -> str:
    """Huella SHA256 de la llave del switch (como `ssh-keygen -l`), para fijarla (pinning)."""
    import base64
    import paramiko
    transporte = paramiko.Transport((host, puerto))
    try:
        transporte.start_client(timeout=10)
        llave = transporte.get_remote_server_key()
    finally:
        transporte.close()
    return "SHA256:" + base64.b64encode(hashlib.sha256(llave.asbytes()).digest()).decode().rstrip("=")


# --------------------------------------------------------------------- CLI
def _conexion_admin() -> psycopg.Connection:
    url = os.environ.get(VARIABLE_ADMIN) or getpass.getpass("URL del dueño de la BD (no se muestra): ")
    return conectar(url, permitir_dueno=True, aplicacion="chontry-admin")


def main(argv=None) -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    cargar_env()
    p = argparse.ArgumentParser(prog="python -m herramientas.admin", description=__doc__.split("\n\n")[0],
                                add_help=False)
    p.add_argument("--ayuda", "-h", action="help", help="muestra esta ayuda")
    sub = p.add_subparsers(dest="orden", required=True)
    sub.add_parser("migrar", help="aplica las migraciones pendientes de db/")
    sub.add_parser("estado", help="muestra migraciones aplicadas y conteos")
    c = sub.add_parser("crear-login", help="crea un login de BD (ct_...) para una persona o un sensor")
    c.add_argument("nombre"); c.add_argument("--rol", required=True, choices=list(GRUPOS))
    c = sub.add_parser("crear-usuario", help="crea la cuenta de la consola (contraseña temporal)")
    c.add_argument("usuario"); c.add_argument("--nombre", required=True)
    c.add_argument("--rol", required=True, choices=["admin", "analista", "auditor"])
    c.add_argument("--login", required=True); c.add_argument("--email")
    c = sub.add_parser("registrar-switch", help="registra un switch gestionado")
    c.add_argument("nombre"); c.add_argument("--ip", required=True); c.add_argument("--fabricante", required=True)
    c.add_argument("--credencial", required=True, help="nombre de la entrada en el keyring")
    c.add_argument("--huella"); c.add_argument("--puerto-span"); c.add_argument("--vlan-cuarentena", type=int, default=999)
    c = sub.add_parser("registrar-segmento", help="registra un segmento de su red (red, VLAN y tipo)")
    c.add_argument("nombre"); c.add_argument("--red", required=True); c.add_argument("--vlan", type=int, required=True)
    c.add_argument("--tipo", default="usuarios", choices=TIPOS_SEGMENTO)
    c = sub.add_parser("registrar-sensor", help="registra un sensor y muestra su CHONTRY_SENSOR_ID")
    c.add_argument("nombre"); c.add_argument("--interfaz", required=True); c.add_argument("--filtro")
    c.add_argument("--ubicacion"); c.add_argument("--switch")
    c = sub.add_parser("configurar", help="cambia un parámetro (valor en JSON)")
    c.add_argument("clave"); c.add_argument("valor")
    c = sub.add_parser("configurar-regla", help="cambia umbrales (JSON) o habilita/deshabilita una regla")
    c.add_argument("codigo"); c.add_argument("--parametros"); c.add_argument("--habilitada", choices=["si", "no"])
    c = sub.add_parser("guardar-credencial-switch", help="guarda usuario/clave del switch en el keyring")
    c.add_argument("referencia"); c.add_argument("--usuario", required=True)
    sub.add_parser("generar-clave-maestra", help="genera la clave AES-256 de evidencias, MFA y buffer")
    c = sub.add_parser("huella-ssh", help="muestra la huella SHA256 de la llave SSH de un switch")
    c.add_argument("host"); c.add_argument("--puerto", type=int, default=22)
    args = p.parse_args(argv)

    try:
        if args.orden == "generar-clave-maestra":
            print("CHONTRY_CLAVE_MAESTRA=" + cripto.generar_clave_maestra())
            print("Guárdela en el .env de cada equipo autorizado (sensor y consolas). Si se pierde, las evidencias "
                  "cifradas y los segundos factores no se pueden recuperar.")
            return 0
        if args.orden == "guardar-credencial-switch":
            guardar_credencial_switch(args.referencia, args.usuario, getpass.getpass("Contraseña del switch: "))
            print(f"Credencial guardada en el keyring del sistema como chontry-switch/{args.referencia}")
            return 0
        if args.orden == "huella-ssh":
            print(huella_ssh(args.host, args.puerto))
            return 0

        with _conexion_admin() as conexion:
            if args.orden == "migrar":
                aplicadas = aplicar_migraciones(conexion)
                print(f"Listo: {len(aplicadas)} migración(es) nueva(s).")
            elif args.orden == "estado":
                with conexion.cursor() as cur:
                    cur.execute("select version, archivo, sha256, aplicada_en from chontry.schema_migraciones order by 1")
                    for v, a, s, f in cur.fetchall():
                        print(f"  {a:40} {s[:12]:12} {f:%Y-%m-%d %H:%M}")
                    for tabla in ("usuarios", "sensores", "switches", "activos", "alertas", "contenciones", "auditoria"):
                        cur.execute(sql.SQL("select count(*) from chontry.{}").format(sql.Identifier(tabla)))
                        print(f"  {tabla:14} {cur.fetchone()[0]}")
            elif args.orden == "crear-login":
                clave = crear_login(conexion, args.nombre, args.rol)
                print(f"Login {args.nombre} creado (grupo {GRUPOS[args.rol]}).")
                print(f"Contraseña (se muestra UNA vez; guárdela en el .env de ese equipo): {clave}")
            elif args.orden == "crear-usuario":
                clave = crear_usuario(conexion, args.usuario, args.nombre, args.rol, args.login, args.email)
                print(f"Usuario {args.usuario} creado. Contraseña temporal (cambio obligatorio al entrar): {clave}")
            elif args.orden == "registrar-switch":
                ident = registrar_switch(conexion, args.nombre, args.ip, args.fabricante, args.credencial,
                                         args.huella, args.puerto_span, args.vlan_cuarentena)
                print(f"Switch {args.nombre} registrado con id {ident}.")
            elif args.orden == "registrar-segmento":
                ident = registrar_segmento(conexion, args.nombre, args.red, args.vlan, args.tipo)
                print(f"Segmento {args.nombre} ({args.red}, VLAN {args.vlan}) registrado con id {ident}.")
            elif args.orden == "registrar-sensor":
                ident = registrar_sensor(conexion, args.nombre, args.interfaz, args.filtro, args.ubicacion, args.switch)
                print(f"Sensor registrado. Ponga en el .env del sensor:\nCHONTRY_SENSOR_ID={ident}")
            elif args.orden == "configurar":
                configurar(conexion, args.clave, json.loads(args.valor))
                print("Configuración actualizada.")
            elif args.orden == "configurar-regla":
                configurar_regla(conexion, args.codigo,
                                 json.loads(args.parametros) if args.parametros else None,
                                 None if args.habilitada is None else args.habilitada == "si")
                print("Regla actualizada.")
    except EntradaInvalida as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except psycopg.Error as exc:
        print(f"Error de base de datos: {exc.diag.message_primary or type(exc).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
