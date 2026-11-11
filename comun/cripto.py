"""Criptografía de ChonTry: contraseñas, cifrado en reposo y segundo factor.

- Contraseñas: Argon2id (argon2-cffi, parámetros por defecto: t=3, m=64 MiB, p=4).   ASVS V2/V6
- Cifrado en reposo: AES-256-GCM con subclaves HKDF-SHA256 por propósito.           ASVS V6
- Segundo factor: TOTP (RFC 6238, 30 s, 6 dígitos).                                ASVS V2.8
Nunca se implementa un algoritmo propio: solo librerías estándar y revisadas.
"""
import base64
import hashlib
import hmac
import os
import secrets
import time
from datetime import datetime, timezone

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from comun.validacion import EntradaInvalida

_HASHER = PasswordHasher()
# Hash fijo para gastar el mismo tiempo cuando el usuario no existe (evita enumeración por tiempo)
_HASH_SEÑUELO = _HASHER.hash(secrets.token_urlsafe(16))

CLAVE_MIN, CLAVE_MAX = 12, 128
_COMUNES = {
    "123456789012", "contraseña123", "contrasena123", "password1234", "qwertyuiop12",
    "administrador", "chontry12345", "1234567890ab", "abc123456789", "seguridad123",
}

ENV_CLAVE_MAESTRA = "CHONTRY_CLAVE_MAESTRA"
SERVICIO_KEYRING = "chontry"


# ------------------------------------------------------------- contraseñas
def hashear_clave(clave: str) -> str:
    return _HASHER.hash(clave)


def verificar_clave(hash_guardado: str | None, clave: str) -> bool:
    try:
        return _HASHER.verify(hash_guardado or _HASH_SEÑUELO, clave) and hash_guardado is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def necesita_rehash(hash_guardado: str) -> bool:
    return _HASHER.check_needs_rehash(hash_guardado)


def validar_clave_nueva(clave: str, usuario: str) -> str:
    """Política de contraseñas: longitud antes que complejidad (ASVS 2.1.1-2.1.7)."""
    if not isinstance(clave, str) or not CLAVE_MIN <= len(clave) <= CLAVE_MAX:
        raise EntradaInvalida(f"La contraseña debe tener entre {CLAVE_MIN} y {CLAVE_MAX} caracteres")
    normal = clave.lower()
    if usuario and usuario.lower() in normal:
        raise EntradaInvalida("La contraseña no puede contener el nombre de usuario")
    if normal in _COMUNES or len(set(clave)) < 4:
        raise EntradaInvalida("La contraseña es demasiado común o repetitiva")
    return clave


def generar_clave_temporal() -> str:
    return secrets.token_urlsafe(15)   # 20 caracteres


# -------------------------------------------------------------- TOTP (2FA)
def generar_secreto_totp() -> str:
    return pyotp.random_base32()


def uri_totp(secreto: str, usuario: str) -> str:
    return pyotp.TOTP(secreto).provisioning_uri(name=usuario, issuer_name="ChonTry")


def paso_totp(secreto: str, codigo: str, ahora: float | None = None) -> int | None:
    """Paso de tiempo (ventana de 30 s) al que corresponde el código, tolerando ±1 paso; None si no coincide."""
    codigo = (codigo or "").strip().replace(" ", "")
    if len(codigo) != 6 or not codigo.isascii() or not codigo.isdigit():
        return None
    totp = pyotp.TOTP(secreto)
    ahora = time.time() if ahora is None else ahora
    for desfase in (0, -1, 1):
        instante = ahora + desfase * totp.interval
        if hmac.compare_digest(totp.at(instante), codigo):
            return totp.timecode(datetime.fromtimestamp(instante, timezone.utc))
    return None


def verificar_totp(secreto: str, codigo: str) -> bool:
    return paso_totp(secreto, codigo) is not None


# ------------------------------------------------- clave maestra y AES-GCM
class ClaveNoDisponible(Exception):
    """No hay clave maestra configurada (variable de entorno o keyring)."""


def generar_clave_maestra() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def cargar_clave_maestra() -> bytes:
    valor = os.environ.get(ENV_CLAVE_MAESTRA)
    if not valor:
        try:
            import keyring
            valor = keyring.get_password(SERVICIO_KEYRING, "clave_maestra")
        except Exception:   # noqa: BLE001 - sin keyring disponible en este sistema
            valor = None
    if not valor:
        raise ClaveNoDisponible("No hay clave maestra: defina CHONTRY_CLAVE_MAESTRA o guárdela en el keyring")
    try:
        clave = base64.b64decode(valor, validate=True)
    except ValueError:
        raise ClaveNoDisponible("La clave maestra no es base64 válido") from None
    if len(clave) != 32:
        raise ClaveNoDisponible("La clave maestra debe tener 32 bytes (AES-256)")
    return clave


class Cifrador:
    """AES-256-GCM con una subclave distinta por propósito (evidencias, mfa, buffer)."""

    def __init__(self, clave_maestra: bytes):
        self._maestra = clave_maestra
        self.id_clave = hashlib.sha256(clave_maestra).hexdigest()[:12]

    @classmethod
    def desde_entorno(cls) -> "Cifrador":
        return cls(cargar_clave_maestra())

    def _subclave(self, proposito: str) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                    info=f"chontry:{proposito}".encode()).derive(self._maestra)

    def cifrar(self, proposito: str, datos: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        return nonce, AESGCM(self._subclave(proposito)).encrypt(nonce, datos, aad)

    def descifrar(self, proposito: str, nonce: bytes, cifrado: bytes, aad: bytes = b"") -> bytes:
        return AESGCM(self._subclave(proposito)).decrypt(nonce, cifrado, aad)

    def cifrar_texto(self, proposito: str, texto: str) -> bytes:
        """nonce + cifrado en un solo bytes (para columnas bytea como mfa_secreto_cifrado)."""
        nonce, cifrado = self.cifrar(proposito, texto.encode())
        return nonce + cifrado

    def descifrar_texto(self, proposito: str, blob: bytes) -> str:
        return self.descifrar(proposito, blob[:12], blob[12:]).decode()
