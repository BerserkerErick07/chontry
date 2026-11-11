"""Carga de configuración desde el archivo .env del proyecto.

Las variables ya definidas en el entorno tienen prioridad: el .env solo
completa lo que falta. El .env nunca va al repositorio (.gitignore).
"""
import os
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def cargar_env(ruta: Path | None = None) -> Path | None:
    """Lee KEY=VALUE del .env (si existe) sin sobrescribir el entorno. Devuelve la ruta leída."""
    ruta = ruta or Path(os.environ.get("CHONTRY_ENV", RAIZ / ".env"))
    if not ruta.is_file():
        return None
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#") or "=" not in linea:
            continue
        clave, valor = linea.split("=", 1)
        clave, valor = clave.strip(), valor.strip()
        if len(valor) >= 2 and valor[0] == valor[-1] and valor[0] in "'\"":
            valor = valor[1:-1]
        os.environ.setdefault(clave, valor)
    return ruta


def carpeta_datos() -> Path:
    """Carpeta para logs y el buffer local del sensor (fuera del repositorio)."""
    carpeta = Path(os.environ.get("CHONTRY_DATOS", RAIZ / "datos"))
    carpeta.mkdir(parents=True, exist_ok=True)
    return carpeta
