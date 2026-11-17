"""Código compartido entre el sensor, la consola y las herramientas de ChonTry."""
import os
import sys
from pathlib import Path


def _asegurar_libpq() -> None:
    """Si Windows (Smart App Control) bloquea el módulo compilado de psycopg, usa la libpq.dll
    del PostgreSQL portable del Centro de control con la implementación en Python puro."""
    try:
        import psycopg  # noqa: F401
        return
    except ImportError:
        pass
    base = Path(os.environ.get("LOCALAPPDATA", Path.home()))
    for carpeta in (base / "ChonTry" / "postgres" / "pgsql" / "bin", base / "chontry-pg" / "pgsql" / "bin"):
        if (carpeta / "libpq.dll").is_file():
            os.environ["PATH"] = f"{carpeta}{os.pathsep}{os.environ.get('PATH', '')}"
            if hasattr(os, "add_dll_directory"):
                os.add_dll_directory(str(carpeta))
            os.environ["PSYCOPG_IMPL"] = "python"
            for nombre in [m for m in sys.modules if m == "psycopg" or m.startswith("psycopg.")]:
                del sys.modules[nombre]
            return


if os.name == "nt":
    _asegurar_libpq()
