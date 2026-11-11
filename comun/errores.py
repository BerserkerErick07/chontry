"""Manejo de errores y logging seguro.

Corrige el hallazgo H3 (fallo 2) de la Clase 3: los errores de la BD revelan
nombres de esquema y tabla. El usuario solo ve un mensaje genérico con un
código de incidente; el detalle va al log interno, que antes de escribirse se
limpia de contraseñas, tokens, cadenas de conexión y correos.

Normas: OWASP ASVS V7 7.4.1 (mensaje genérico) y 7.1.1 (no registrar
credenciales) · NIST SSDF PW.9.
"""
import logging
import re
import uuid

MENSAJE_GENERICO = "Ocurrió un error. Contacte al administrador. Código: {codigo}"
# El mismo texto para usuario inexistente, contraseña errada o cuenta bloqueada:
# así no se puede saber qué usuarios existen (enumeración).
MENSAJE_CREDENCIALES = "Credenciales inválidas."

_PATRONES_SECRETOS = [
    (re.compile(r"(postgres(?:ql)?://[^:/\s]+:)[^@\s]+@"), r"\1***@"),
    (re.compile(r"npg_[A-Za-z0-9]+"), "npg_***"),
    (re.compile(r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key)\s*[=:]\s*\S+"), r"\1=***"),
    (re.compile(r"\$argon2id\$\S+"), "$argon2id$***"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "***@***"),
]


def limpiar(texto: str) -> str:
    """Reemplaza secretos y datos personales conocidos por ***."""
    for patron, reemplazo in _PATRONES_SECRETOS:
        texto = patron.sub(reemplazo, texto)
    return texto


class FormateadorSeguro(logging.Formatter):
    """Limpia el registro ya formateado, incluidas las trazas de pila."""

    def format(self, record: logging.LogRecord) -> str:
        return limpiar(super().format(record))


def configurar_log(ruta: str = "chontry.log") -> logging.Logger:
    logger = logging.getLogger("chontry")
    if not logger.handlers:
        manejador = logging.FileHandler(ruta, encoding="utf-8")
        manejador.setFormatter(FormateadorSeguro("%(asctime)s %(levelname)s %(name)s %(message)s"))
        logger.addHandler(manejador)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def manejar_error(exc: BaseException, contexto: str) -> str:
    """Registra el detalle técnico y devuelve el mensaje que puede ver el usuario."""
    codigo = uuid.uuid4().hex[:8]
    logging.getLogger("chontry").error("[%s] %s", codigo, contexto, exc_info=exc)
    return MENSAJE_GENERICO.format(codigo=codigo)
