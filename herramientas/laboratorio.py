"""Monta un laboratorio completo de ChonTry en un PostgreSQL de pruebas.

Crea (o recrea) la base de datos, aplica las migraciones, crea los logins por
rol, usuarios con contraseña y segundo factor, el switch y el sensor de
laboratorio, marca los activos protegidos y escribe todo en `.env.lab`.

    set CHONTRY_PRUEBAS_PG_ADMIN=postgresql://postgres:CONTRASENA@localhost:5432/postgres
    python -m herramientas.laboratorio

SOLO para pruebas: nunca lo ejecute contra la base de datos de producción.
`.env.lab` contiene credenciales de prueba y está en .gitignore.
"""
import os
import sys
from urllib.parse import urlsplit, urlunsplit

import psycopg
import pyotp
from psycopg import sql

from comun import cripto
from comun.config import RAIZ, cargar_env
from herramientas import admin

BD = os.environ.get("CHONTRY_LAB_BD", "chontry_lab")
ROLES = ("sensor", "admin", "analista", "auditor")
# Activos de la red de laboratorio que nunca se deben aislar (ver herramientas/generar_pcaps.py)
PROTEGIDOS = [("00:1a:2b:00:00:01", "10.10.20.1", "gw-vlan20", 5),
              ("02:00:0a:0a:1e:0a", "10.10.30.10", "dc01", 5)]


def _url_con_bd(url: str, bd: str, usuario: str | None = None, clave: str | None = None) -> str:
    partes = urlsplit(url)
    netloc = partes.netloc.split("@", 1)[1] if "@" in partes.netloc else partes.netloc
    if usuario:
        netloc = f"{usuario}:{clave}@{netloc}"
    else:
        netloc = partes.netloc
    return urlunsplit(partes._replace(netloc=netloc, path=f"/{bd}"))


def desmontar(url_superusuario: str, bd: str = BD, prefijo: str = "ct_lab") -> None:
    with psycopg.connect(url_superusuario, autocommit=True) as c:
        c.execute(sql.SQL("drop database if exists {} with (force)").format(sql.Identifier(bd)))
        for rol in ROLES:
            c.execute(sql.SQL("drop role if exists {}").format(sql.Identifier(f"{prefijo}_{rol}")))


def montar(url_superusuario: str, salida=print, bd: str = BD, prefijo: str = "ct_lab") -> dict[str, str]:
    if urlsplit(url_superusuario).hostname not in ("localhost", "127.0.0.1", "::1"):
        raise SystemExit("El laboratorio solo se monta en un PostgreSQL local (localhost)")
    LOGINS = {f"{prefijo}_{rol}": rol for rol in ROLES}
    sufijo = prefijo.removeprefix("ct_")
    USUARIOS = [(f"admin.{sufijo}", "Administrador de laboratorio", "admin", f"{prefijo}_admin"),
                (f"analista.{sufijo}", "Analista de laboratorio", "analista", f"{prefijo}_analista"),
                (f"auditor.{sufijo}", "Auditor de laboratorio", "auditor", f"{prefijo}_auditor")]
    desmontar(url_superusuario, bd, prefijo)
    with psycopg.connect(url_superusuario, autocommit=True) as c:
        c.execute(sql.SQL("create database {}").format(sql.Identifier(bd)))
    salida(f"Base de datos {bd} creada")

    entorno: dict[str, str] = {}
    url_admin_bd = _url_con_bd(url_superusuario, bd)
    with admin.conectar(url_admin_bd, permitir_dueno=True) as c:
        admin.aplicar_migraciones(c, salida=lambda m: salida(m))
        claves = {login: admin.crear_login(c, login, rol) for login, rol in LOGINS.items()}
        maestra = cripto.generar_clave_maestra()
        cifrador = cripto.Cifrador(__import__("base64").b64decode(maestra))
        for usuario, nombre, rol, login in USUARIOS:
            clave = cripto.generar_clave_temporal() + "Lab"
            admin.crear_usuario(c, usuario, nombre, rol, login, clave=clave)
            secreto = cripto.generar_secreto_totp()
            with c.transaction():
                c.execute("update chontry.usuarios set mfa_secreto_cifrado = %s, debe_cambiar_clave = false "
                          "where usuario = %s", (cifrador.cifrar_texto("mfa", secreto), usuario))
            etiqueta = usuario.split(".")[0].upper()
            entorno[f"LAB_{etiqueta}_USUARIO"] = usuario
            entorno[f"LAB_{etiqueta}_CLAVE"] = clave
            entorno[f"LAB_{etiqueta}_TOTP"] = secreto
        switch_id = admin.registrar_switch(c, "sw-lab-01", "10.10.10.2", "cisco_ios", "sw-lab-01",
                                           puerto_span="Gi1/0/48")
        sensor_id = admin.registrar_sensor(c, "sensor-lab-01", "eth0", "not port 22", "Laboratorio", "sw-lab-01")
        with c.transaction():
            for mac, ip, nombre, criticidad in PROTEGIDOS:
                c.execute("""insert into chontry.activos (mac, ip, hostname, switch_id, puerto_switch, vlan_actual,
                                                          criticidad, protegido, segmento_id)
                             values (%s, %s, %s, %s, %s, %s, %s, true,
                                     (select id from chontry.segmentos_red where %s::inet << red))""",
                          (mac, ip, nombre, switch_id, "Gi1/0/1", 20 if ip.startswith("10.10.20") else 30,
                           criticidad, ip))
        admin.configurar(c, "contencion.modo_ejecucion", "simulado")
    salida("Logins, usuarios con TOTP, switch, sensor y activos protegidos creados")

    entorno.update({
        "CHONTRY_DB_URL": _url_con_bd(url_superusuario, bd, f"{prefijo}_admin", claves[f"{prefijo}_admin"]),
        "CHONTRY_DB_URL_ANALISTA": _url_con_bd(url_superusuario, bd, f"{prefijo}_analista", claves[f"{prefijo}_analista"]),
        "CHONTRY_DB_URL_AUDITOR": _url_con_bd(url_superusuario, bd, f"{prefijo}_auditor", claves[f"{prefijo}_auditor"]),
        "CHONTRY_DB_URL_SENSOR": _url_con_bd(url_superusuario, bd, f"{prefijo}_sensor", claves[f"{prefijo}_sensor"]),
        "CHONTRY_DB_URL_ADMIN": url_admin_bd,
        "CHONTRY_SENSOR_ID": sensor_id,
        "CHONTRY_CLAVE_MAESTRA": maestra,
    })
    return entorno


def escribir_env(entorno: dict[str, str], ruta=RAIZ / ".env.lab") -> None:
    lineas = ["# Laboratorio local de ChonTry (herramientas/laboratorio.py). CREDENCIALES DE PRUEBA: no subir a git.",
              "# Úselo con:  set CHONTRY_ENV=.env.lab   (PowerShell: $env:CHONTRY_ENV='.env.lab')"]
    lineas += [f"{clave}={valor}" for clave, valor in entorno.items()]
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")


def codigo_totp(secreto: str) -> str:
    return pyotp.TOTP(secreto).now()


if __name__ == "__main__":
    cargar_env(RAIZ / ".env.pruebas")
    url = os.environ.get("CHONTRY_PRUEBAS_PG_ADMIN")
    if not url:
        sys.exit("Defina CHONTRY_PRUEBAS_PG_ADMIN con la URL del superusuario de un PostgreSQL LOCAL")
    datos = montar(url)
    escribir_env(datos)
    print(f"Listo. Credenciales de prueba en {RAIZ / '.env.lab'}")
    print("Consola: $env:CHONTRY_ENV='.env.lab'; .venv\\Scripts\\python.exe -m consola")
