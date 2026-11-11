"""Punto de entrada de la consola:  python -m consola   (desde la carpeta chontry)

    --captura DIR   modo demostración sin interacción: simula unos segundos, guarda una
                    imagen de cada sección en DIR y termina.
"""
import argparse
import os
import sys
import time
from pathlib import Path

import psycopg
from PySide6.QtCore import QEvent, QObject, QTimer, Signal
from PySide6.QtWidgets import QApplication, QDialog, QMessageBox

from comun.config import cargar_env, carpeta_datos
from comun.db import ConfiguracionInsegura, conectar
from comun.errores import configurar_log, manejar_error
from consola import tema
from consola.acceso import AccesoDenegado, ServicioAcceso, cifrador_local
from consola.datos import CONFIG_LOCAL, REGLAS_LOCALES
from consola.dialogos_acceso import DialogoAcceso, DialogoPrimerIngreso, DialogoTotp, hay_base_de_datos
from consola.estado import Estado
from consola.simulador import SensorSimulado
from consola.ventana import VentanaPrincipal
from consola.vistas import DialogoContencion

REINICIAR = 1001


class VigilanteInactividad(QObject):
    """Cierra la sesión tras N minutos sin teclado ni ratón (ASVS V3.3)."""
    expirada = Signal()

    def __init__(self, minutos: int):
        super().__init__()
        self._limite = max(1, minutos) * 60
        self._ultimo = time.monotonic()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._revisar)
        self._timer.start(15000)

    def eventFilter(self, objeto, evento):  # noqa: N802 - nombre de Qt
        if evento.type() in (QEvent.KeyPress, QEvent.MouseButtonPress, QEvent.MouseMove, QEvent.Wheel):
            self._ultimo = time.monotonic()
        return False

    def _revisar(self):
        if time.monotonic() - self._ultimo > self._limite:
            self._timer.stop()
            self.expirada.emit()


def _argumentos():
    parser = argparse.ArgumentParser(prog="consola", description="ChonTry · consola de escritorio")
    parser.add_argument("--captura", type=Path, help="carpeta donde guardar capturas del modo demostración")
    parser.add_argument("--segundos", type=int, default=20, help="segundos de simulación antes de capturar")
    parser.add_argument("--rol", choices=("admin", "analista"), default="admin")
    return parser.parse_args()


def _capturar_demo(app, ventana: VentanaPrincipal, carpeta: Path) -> None:
    carpeta.mkdir(parents=True, exist_ok=True)
    estado = ventana.estado
    pendiente = next((c for c in estado.contenciones if c.estado == "propuesta"), None)
    if pendiente and estado.es_admin:
        estado.aprobar(pendiente.id)
    alerta = next((a for a in estado.alertas if a.estado == "nueva"), None)
    if alerta:
        estado.cambiar_estado_alerta(alerta.id, "en_revision")
    for indice, nombre in enumerate(ventana.SECCIONES):
        ventana.navegacion.setCurrentRow(indice)
        vista = ventana.vistas[indice]
        if hasattr(vista, "tabla") and vista.modelo.rowCount():
            vista.tabla.selectRow(0)
        if nombre == "Auditoría":
            vista._verificar()
        app.processEvents()
        ventana.grab().save(str(carpeta / f"{indice + 1:02d}_{nombre.lower().replace('í', 'i')}.png"))
    dialogo = DialogoContencion(estado, ventana)
    dialogo.ip.setText("10.10.20.999")
    dialogo.puerto.setText("Gi1/0/1; reload")
    dialogo.motivo.setText("prueba de inyección")
    dialogo._aceptar()
    dialogo.show()
    app.processEvents()
    dialogo.grab().save(str(carpeta / "07_validacion_contencion.png"))
    dialogo.close()
    if estado.es_admin:
        vista = ventana.vistas[ventana.SECCIONES.index("Auditoría")]
        ventana.navegacion.setCurrentRow(ventana.SECCIONES.index("Auditoría"))
        vista._alterar()
        vista._verificar()
        app.processEvents()
        ventana.grab().save(str(carpeta / "06_auditoria_manipulada.png"))
    app.quit()


def iniciar_sesion():
    """Muestra el acceso. Devuelve (estado, sensor_simulado | None) o None si se cancela."""
    contexto: dict = {}

    def al_entrar(usuario: str, clave: str) -> bool:
        try:
            conexion = conectar(aplicacion="chontry-consola")
        except ConfiguracionInsegura as exc:
            raise AccesoDenegado(f"Configuración insegura: {exc}") from None
        except psycopg.Error as exc:
            raise AccesoDenegado(manejar_error(exc, "conectar a la base de datos")) from None
        servicio = ServicioAcceso(conexion, cifrador_local())
        try:
            servicio.verificar_clave(usuario, clave)
            if servicio.requiere_totp() and DialogoTotp(servicio).exec() != QDialog.Accepted:
                raise AccesoDenegado("Inicio de sesión cancelado.")
            if (servicio.requiere_cambio_clave() or servicio.requiere_enrolar()) and \
                    DialogoPrimerIngreso(servicio).exec() != QDialog.Accepted:
                raise AccesoDenegado("Debe completar la configuración de su cuenta para continuar.")
            contexto["cuenta"] = servicio.completar()
        except AccesoDenegado:
            conexion.close()
            raise
        except psycopg.Error as exc:
            conexion.close()
            raise AccesoDenegado(manejar_error(exc, "inicio de sesión")) from None
        contexto["conexion"], contexto["servicio"] = conexion, servicio
        return True

    dialogo = DialogoAcceso(hay_base_de_datos(), al_entrar)
    if dialogo.exec() != QDialog.Accepted:
        return None
    if dialogo.modo == "demo":
        usuario, rol = dialogo.datos_demo()
        estado = Estado(usuario, rol, REGLAS_LOCALES, CONFIG_LOCAL, "Local (demostración)")
        return estado, SensorSimulado(estado)
    from consola.repositorio import EstadoNeon
    servicio = contexto["servicio"]
    estado = EstadoNeon(contexto["conexion"], os.environ["CHONTRY_DB_URL"], contexto["cuenta"], servicio.sesion_id,
                        servicio.cifrador)
    return estado, None


def main() -> int:
    args = _argumentos()
    cargar_env()
    configurar_log(str(carpeta_datos() / "consola.log"))
    app = QApplication(sys.argv)
    app.setApplicationName("ChonTry")
    app.setStyleSheet(tema.QSS)

    if args.captura:
        estado = Estado("erick", args.rol, REGLAS_LOCALES, CONFIG_LOCAL, "Local (demostración)")
        sensor = SensorSimulado(estado, intervalo_ms=150, probabilidad=0.12)
        ventana = VentanaPrincipal(estado)
        ventana.show()
        sensor.iniciar()
        QTimer.singleShot(args.segundos * 1000, lambda: _capturar_demo(app, ventana, args.captura))
        return app.exec()

    while True:
        sesion = iniciar_sesion()
        if sesion is None:
            return 0
        estado, sensor = sesion
        ventana = VentanaPrincipal(estado)
        minutos = int(getattr(estado, "config", CONFIG_LOCAL).get("sesion.inactividad_minutos", 15))
        vigilante = VigilanteInactividad(minutos)
        app.installEventFilter(vigilante)

        def terminar(mensaje: str | None = None, motivo: str = "cierre_sesion"):
            if mensaje:
                QMessageBox.information(ventana, "Sesión cerrada", mensaje)
            ventana._motivo_cierre = motivo
            app.exit(REINICIAR)

        ventana.cerrar_sesion.connect(lambda: terminar())
        vigilante.expirada.connect(lambda: terminar("La sesión se cerró por inactividad.", "cierre_por_inactividad"))
        if hasattr(estado, "sesion_terminada"):
            estado.sesion_terminada.connect(lambda m: terminar(m, "sesion_revocada"))
        ventana.show()
        if sensor:
            sensor.iniciar()
        codigo = app.exec()
        app.removeEventFilter(vigilante)
        if sensor:
            sensor.detener()
        if hasattr(estado, "cerrar"):
            estado.cerrar(getattr(ventana, "_motivo_cierre", "cierre_sesion"))
        ventana.close()
        ventana.deleteLater()
        if codigo != REINICIAR:
            return codigo


if __name__ == "__main__":
    sys.exit(main())
