"""Muestra los usuarios de prueba del laboratorio y su código TOTP actual (se actualiza solo).

    $env:CHONTRY_ENV='.env.lab'; python -m herramientas.acceso_lab
SOLO para el laboratorio local: lee las credenciales de prueba de .env.lab.
"""
import os
import sys
import time

import pyotp

from comun.config import cargar_env


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    cargar_env()
    usuarios = [p for p in ("ADMIN", "ANALISTA", "AUDITOR") if os.environ.get(f"LAB_{p}_USUARIO")]
    if not usuarios:
        print("No hay laboratorio: ejecute python -m herramientas.laboratorio")
        return 1
    try:
        while True:
            os.system("cls" if os.name == "nt" else "clear")  # nosec B605 - limpia la pantalla, sin datos externos
            print("ChonTry · usuarios del LABORATORIO (credenciales de prueba)\n")
            restante = 30 - int(time.time()) % 30
            for p in usuarios:
                codigo = pyotp.TOTP(os.environ[f"LAB_{p}_TOTP"]).now()
                print(f"  {p.title():9} usuario: {os.environ[f'LAB_{p}_USUARIO']:14} "
                      f"contraseña: {os.environ[f'LAB_{p}_CLAVE']:26} código: {codigo}")
            print(f"\nLos códigos cambian en {restante:2d} s. Cada código sirve una sola vez.  (Ctrl+C para cerrar)")
            time.sleep(1)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
