"""Centro de control de ChonTry:  python -m lanzador   (o doble clic en «Iniciar ChonTry.bat» / ChonTry.exe)."""
import sys

from PySide6.QtWidgets import QApplication

from comun.config import carpeta_datos
from comun.errores import configurar_log
from consola import tema
from consola.icono import icono
from lanzador.servicios import Rutas


def main() -> int:
    rutas = Rutas()
    configurar_log(str(rutas.datos / "centro_de_control.log"))
    carpeta_datos()
    app = QApplication(sys.argv)
    app.setApplicationName("ChonTry")
    app.setWindowIcon(icono())
    app.setStyleSheet(tema.QSS)
    from lanzador.ventana import CentroDeControl
    ventana = CentroDeControl()
    ventana.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
