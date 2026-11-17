"""Punto de entrada único de ChonTry (es el que se empaqueta como ChonTry.exe).

    ChonTry.exe                     Centro de control (enciende todo)
    ChonTry.exe consola [--env F]   consola de escritorio
    ChonTry.exe sensor ...          sensor (mismas opciones que python -m sensor)
    ChonTry.exe admin ...           herramienta de administración de la BD
"""
import multiprocessing
import sys


def main() -> int:
    orden, argumentos = (sys.argv[1], sys.argv[2:]) if len(sys.argv) > 1 else ("centro", [])
    sys.argv = [sys.argv[0], *argumentos]
    if orden == "consola":
        from consola.__main__ import main as principal
        return principal()
    if orden == "sensor":
        from sensor.__main__ import main as principal
        return principal(argumentos)
    if orden == "admin":
        from herramientas.admin import main as principal
        return principal(argumentos)
    from lanzador.__main__ import main as principal
    return principal()


if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
