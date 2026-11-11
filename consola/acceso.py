"""Autenticación de la consola contra la base de datos.

Dos capas:
  1. El login de PostgreSQL de este equipo (CHONTRY_DB_URL, uno por persona).
  2. La cuenta de la app: contraseña Argon2id + segundo factor TOTP.
El conteo de intentos y el bloqueo los aplica la BD (registrar_login); el
mensaje de error es siempre el mismo para no revelar qué falló (ASVS V2/V7).
"""
from __future__ import annotations

import hashlib
import json
import platform
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone

import psycopg

from comun import cripto
from comun.cripto import Cifrador, ClaveNoDisponible
from comun.errores import MENSAJE_CREDENCIALES, manejar_error
from comun.validacion import EntradaInvalida


class AccesoDenegado(Exception):
    """Autenticación fallida. El mensaje es apto para mostrar al usuario."""


@dataclass
class Cuenta:
    id: str
    usuario: str
    rol: str
    hash_clave: str
    mfa_cifrado: bytes | None
    activo: bool
    bloqueado_hasta: datetime | None
    debe_cambiar_clave: bool


class ServicioAcceso:
    def __init__(self, conexion: psycopg.Connection, cifrador: Cifrador | None):
        self.conexion = conexion
        self.cifrador = cifrador
        self.cuenta: Cuenta | None = None
        self.sesion_id: str | None = None
        self._clave_ok = False
        self._totp_ok = False

    # --------------------------------------------------------- utilidades
    def _config(self, clave: str, defecto):
        with self.conexion.cursor() as cur:
            cur.execute("select valor from chontry.configuracion where clave = %s", (clave,))
            fila = cur.fetchone()
        return fila[0] if fila else defecto

    def _registrar(self, exito: bool) -> bool:
        with self.conexion.transaction(), self.conexion.cursor() as cur:
            cur.execute("select chontry.registrar_login(%s)", (exito,))
            return bool(cur.fetchone()[0])

    def _leer_cuenta(self) -> Cuenta | None:
        with self.conexion.cursor() as cur:
            cur.execute("select * from chontry.mis_credenciales()")
            fila = cur.fetchone()
        if fila is None:
            return None
        return Cuenta(str(fila[0]), fila[1], fila[2], fila[3], bytes(fila[4]) if fila[4] else None,
                      fila[5], fila[6], fila[7])

    @property
    def mfa_obligatorio(self) -> bool:
        return bool(self._config("auth.mfa_obligatorio", True))

    # ------------------------------------------------------------- pasos
    def verificar_clave(self, usuario: str, clave: str) -> None:
        """Paso 1. Lanza AccesoDenegado con un mensaje genérico si algo no cuadra."""
        cuenta = self._leer_cuenta()
        if cuenta is None or cuenta.usuario != usuario.strip().lower() or not cuenta.activo:
            cripto.verificar_clave(None, clave)       # mismo tiempo de respuesta
            if cuenta is not None:
                self._registrar(False)
            raise AccesoDenegado(MENSAJE_CREDENCIALES)
        if cuenta.bloqueado_hasta and cuenta.bloqueado_hasta > datetime.now(timezone.utc):
            cripto.verificar_clave(None, clave)
            raise AccesoDenegado(MENSAJE_CREDENCIALES + " Si el problema persiste, contacte al administrador.")
        if not cripto.verificar_clave(cuenta.hash_clave, clave):
            self._registrar(False)
            raise AccesoDenegado(MENSAJE_CREDENCIALES)
        self.cuenta = cuenta
        self._clave_ok = True
        if cripto.necesita_rehash(cuenta.hash_clave):
            self._guardar_clave(clave)

    def requiere_totp(self) -> bool:
        return self.cuenta is not None and self.cuenta.mfa_cifrado is not None

    def requiere_enrolar(self) -> bool:
        return self.cuenta is not None and self.cuenta.mfa_cifrado is None and self.mfa_obligatorio

    def requiere_cambio_clave(self) -> bool:
        return self.cuenta is not None and self.cuenta.debe_cambiar_clave

    def _exigir_cifrador(self) -> Cifrador:
        if self.cifrador is None:
            raise AccesoDenegado("Este equipo no tiene configurada la clave maestra (CHONTRY_CLAVE_MAESTRA). "
                                 "Contacte al administrador.")
        return self.cifrador

    def verificar_totp(self, codigo: str) -> None:
        """Paso 2 (si la cuenta tiene segundo factor)."""
        if not self._clave_ok or self.cuenta is None or self.cuenta.mfa_cifrado is None:
            raise AccesoDenegado(MENSAJE_CREDENCIALES)
        try:
            secreto = self._exigir_cifrador().descifrar_texto("mfa", self.cuenta.mfa_cifrado)
        except AccesoDenegado:
            raise
        except Exception:   # noqa: BLE001 - clave maestra distinta a la usada al enrolar
            raise AccesoDenegado("No se pudo validar el segundo factor en este equipo. Contacte al administrador.") \
                from None
        paso = cripto.paso_totp(secreto, codigo)
        if paso is None:
            self._registrar(False)
            raise AccesoDenegado("Código de verificación inválido.")
        self._consumir(paso)
        self._totp_ok = True

    def _consumir(self, paso: int) -> None:
        """Cada código sirve una sola vez (ASVS 2.8.4)."""
        with self.conexion.transaction(), self.conexion.cursor() as cur:
            cur.execute("select chontry.consumir_totp(%s)", (paso,))
            if not cur.fetchone()[0]:
                raise AccesoDenegado("Ese código ya se usó. Espere el siguiente código de su aplicación.")

    def cambiar_clave(self, nueva: str, confirmacion: str) -> None:
        if not self._clave_ok or self.cuenta is None:
            raise AccesoDenegado(MENSAJE_CREDENCIALES)
        if nueva != confirmacion:
            raise EntradaInvalida("Las contraseñas no coinciden")
        cripto.validar_clave_nueva(nueva, self.cuenta.usuario)
        if cripto.verificar_clave(self.cuenta.hash_clave, nueva):
            raise EntradaInvalida("La nueva contraseña debe ser distinta de la anterior")
        self._guardar_clave(nueva)
        self.cuenta.debe_cambiar_clave = False

    def _guardar_clave(self, clave: str) -> None:
        nuevo = cripto.hashear_clave(clave)
        with self.conexion.transaction(), self.conexion.cursor() as cur:
            cur.execute("""update chontry.usuarios set password_hash = %s, debe_cambiar_clave = false
                           where rol_bd = current_user""", (nuevo,))
        self.cuenta.hash_clave = nuevo

    def nuevo_secreto_totp(self) -> tuple[str, str]:
        """Devuelve (secreto, uri otpauth) para mostrar el QR. Aún no se guarda."""
        self._exigir_cifrador()
        secreto = cripto.generar_secreto_totp()
        return secreto, cripto.uri_totp(secreto, self.cuenta.usuario)

    def enrolar_totp(self, secreto: str, codigo: str) -> None:
        if not self._clave_ok or self.cuenta is None:
            raise AccesoDenegado(MENSAJE_CREDENCIALES)
        paso = cripto.paso_totp(secreto, codigo)
        if paso is None:
            raise EntradaInvalida("El código no coincide. Revise la hora del teléfono y vuelva a intentarlo.")
        cifrado = self._exigir_cifrador().cifrar_texto("mfa", secreto)
        with self.conexion.transaction(), self.conexion.cursor() as cur:
            cur.execute("update chontry.usuarios set mfa_secreto_cifrado = %s where rol_bd = current_user", (cifrado,))
        self._consumir(paso)
        self.cuenta.mfa_cifrado = cifrado
        self._totp_ok = True

    def completar(self) -> dict:
        """Último paso: la BD confirma (bloqueos) y se abre la sesión. Devuelve la cuenta para la consola."""
        if not self._clave_ok or self.cuenta is None:
            raise AccesoDenegado(MENSAJE_CREDENCIALES)
        if (self.requiere_totp() or self.mfa_obligatorio) and not self._totp_ok:
            raise AccesoDenegado("Falta el segundo factor.")
        if self.cuenta.debe_cambiar_clave:
            raise AccesoDenegado("Debe cambiar la contraseña antes de continuar.")
        if not self._registrar(True):
            raise AccesoDenegado(MENSAJE_CREDENCIALES)
        token = secrets.token_urlsafe(32)
        minutos = int(self._config("sesion.duracion_minutos", 480))
        with self.conexion.transaction(), self.conexion.cursor() as cur:
            cur.execute("""insert into chontry.sesiones (usuario_id, token_hash, equipo, expira_en)
                           values (%s, %s, %s, now() + make_interval(mins => %s)) returning id""",
                        (self.cuenta.id, hashlib.sha256(token.encode()).digest(), platform.node()[:120], minutos))
            self.sesion_id = str(cur.fetchone()[0])
            cur.execute("""insert into chontry.auditoria (actor_tipo, actor_id, accion, entidad, entidad_id, detalle)
                           values ('usuario', %s, 'inicio_sesion', 'sesiones', %s, %s::jsonb)""",
                        (self.cuenta.usuario, self.sesion_id,
                         json.dumps({"equipo": platform.node()[:60], "segundo_factor": self._totp_ok})))
        return {"id": self.cuenta.id, "usuario": self.cuenta.usuario, "rol": self.cuenta.rol}


def cifrador_local() -> Cifrador | None:
    try:
        return Cifrador.desde_entorno()
    except ClaveNoDisponible:
        return None


def describir_error(exc: Exception) -> str:
    return manejar_error(exc, "inicio de sesión")
