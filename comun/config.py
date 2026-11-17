"""Carga de configuración desde el archivo .env del proyecto.

Las variables ya definidas en el entorno tienen prioridad: el .env solo
completa lo que falta. El .env nunca va al repositorio (.gitignore).
"""
import os
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
# Dentro de ChonTry.exe (PyInstaller) los archivos del programa son de solo lectura:
# lo que se escribe (laboratorio, logs, base portable) va a la carpeta del usuario.
CONGELADO = bool(getattr(sys, "frozen", False))


def casa_usuario() -> Path:
    """Carpeta de datos del usuario para el Centro de control y el laboratorio."""
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    carpeta = Path(os.environ.get("CHONTRY_CASA", Path(base) / "ChonTry"))
    carpeta.mkdir(parents=True, exist_ok=True)
    return carpeta


def leer_env(ruta: Path) -> dict[str, str]:
    """Lee un archivo KEY=VALUE sin tocar el entorno del proceso."""
    datos: dict[str, str] = {}
    if not Path(ruta).is_file():
        return datos
    for linea in Path(ruta).read_text(encoding="utf-8").splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#") or "=" not in linea:
            continue
        clave, valor = linea.split("=", 1)
        valor = valor.strip()
        if len(valor) >= 2 and valor[0] == valor[-1] and valor[0] in "'\"":
            valor = valor[1:-1]
        datos[clave.strip()] = valor
    return datos


def cargar_env(ruta: Path | None = None) -> Path | None:
    """Lee KEY=VALUE del .env (si existe) sin sobrescribir el entorno. Devuelve la ruta leída."""
    ruta = Path(ruta or os.environ.get("CHONTRY_ENV", RAIZ / ".env"))
    if not ruta.is_absolute() and not ruta.is_file():
        ruta = RAIZ / ruta
    if not ruta.is_file():
        return None
    for clave, valor in leer_env(ruta).items():
        os.environ.setdefault(clave, valor)
    return ruta


def preparar_salida() -> None:
    """Sin consola (pythonw o ChonTry.exe) sys.stdout es None: se protege antes de escribir."""
    for flujo in (sys.stdout, sys.stderr):
        if flujo is not None and hasattr(flujo, "reconfigure"):
            flujo.reconfigure(encoding="utf-8", errors="replace")


def usar_env(argv: list[str]) -> list[str]:
    """Quita `--env RUTA` de los argumentos y lo deja en CHONTRY_ENV (lo usa el Centro de control)."""
    if "--env" in argv:
        i = argv.index("--env")
        if i + 1 < len(argv):
            os.environ["CHONTRY_ENV"] = argv[i + 1]
            return argv[:i] + argv[i + 2:]
    return argv


def carpeta_datos() -> Path:
    """Carpeta para logs y el buffer local del sensor (fuera del repositorio)."""
    defecto = casa_usuario() / "datos" if CONGELADO else RAIZ / "datos"
    carpeta = Path(os.environ.get("CHONTRY_DATOS", defecto))
    carpeta.mkdir(parents=True, exist_ok=True)
    return carpeta
