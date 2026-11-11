"""Conexión a PostgreSQL (Neon u otro) con TLS que valida el certificado del servidor.

``sslmode=require`` cifra el canal pero no autentica al servidor (equivale a
``verify=False``). Este módulo exige ``verify-full`` + ``channel_binding``.
Única excepción: un servidor en el propio equipo (localhost), cuyo tráfico no
sale de la máquina; se usa para desarrollo y pruebas.

Normas: OWASP ASVS V9 (comunicaciones) · NIST SSDF PW.9 (configuración segura).
"""
import os
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit

import certifi
import psycopg

VARIABLE_ENTORNO = "CHONTRY_DB_URL"
VARIABLE_ADMIN = "CHONTRY_DB_URL_ADMIN"
PARAMETROS_OBLIGATORIOS = {"sslmode": "verify-full", "channel_binding": "require"}
ROLES_DUENO = {"neondb_owner", "postgres"}
HOSTS_LOCALES = {"localhost", "127.0.0.1", "::1"}


class ConfiguracionInsegura(Exception):
    """La configuración de conexión no cumple la política de seguridad."""


def url_segura(url: str, permitir_dueno: bool = False) -> str:
    """Devuelve la URL lista para conectar o lanza ConfiguracionInsegura.

    Los mensajes de error nunca incluyen la URL: contiene la contraseña.
    ``permitir_dueno`` solo lo usa la herramienta de administración (migraciones).
    """
    partes = urlsplit(url)
    if partes.scheme not in ("postgresql", "postgres"):
        raise ConfiguracionInsegura("Esquema de conexión no soportado")
    if not permitir_dueno and partes.username in ROLES_DUENO:
        raise ConfiguracionInsegura("La aplicación no puede usar el rol dueño de la base de datos")

    parametros = {clave: valores[-1] for clave, valores in parse_qs(partes.query).items()}
    if partes.hostname in HOSTS_LOCALES:
        # Loopback: el tráfico no sale del equipo. Se acepta sin TLS (desarrollo y pruebas).
        if parametros.get("sslmode") == "verify-full":
            parametros.setdefault("sslrootcert", certifi.where())
        return urlunsplit(partes._replace(query=urlencode(parametros, quote_via=quote)))

    for clave, valor in PARAMETROS_OBLIGATORIOS.items():
        if parametros.get(clave) != valor:
            raise ConfiguracionInsegura(f"La conexión debe usar {clave}={valor}")
    # CA de confianza: el paquete de certifi, igual en Windows, Linux y macOS. Las libpq
    # antiguas (la 14 que traía psycopg 3.2 en Windows) no soportan sslrootcert=system.
    parametros.setdefault("sslrootcert", certifi.where())
    return urlunsplit(partes._replace(query=urlencode(parametros, quote_via=quote)))


def conectar(url: str | None = None, timeout_seg: int = 10, permitir_dueno: bool = False,
             aplicacion: str = "chontry") -> psycopg.Connection:
    """Abre una conexión en modo autocommit; las escrituras usan ``with conexion.transaction()``."""
    url = url or os.environ.get(VARIABLE_ENTORNO)
    if not url:
        raise ConfiguracionInsegura(f"Falta la variable de entorno {VARIABLE_ENTORNO}")
    # prepare_threshold=None: el pooler de Neon (PgBouncer) no conserva sentencias preparadas
    return psycopg.connect(url_segura(url, permitir_dueno), application_name=aplicacion,
                           connect_timeout=timeout_seg, autocommit=True, prepare_threshold=None)
