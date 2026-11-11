"""Capturas de la consola REAL conectada al laboratorio (evidencia para informes y manuales).

Requiere el laboratorio montado (python -m herramientas.laboratorio) y alertas cargadas
(python -m sensor --pcap pruebas/pcaps/todos_los_ataques.pcap con CHONTRY_ENV=.env.lab).

    $env:CHONTRY_ENV='.env.lab'; python -m herramientas.capturas_consola capturas/consola
Inicia sesión de verdad (Argon2id + TOTP) con los usuarios de prueba de .env.lab.
"""
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pyotp
from PySide6.QtWidgets import QApplication

from comun.config import RAIZ, cargar_env
from comun.db import conectar
from consola import tema
from consola.acceso import ServicioAcceso, cifrador_local
from consola.dialogos_acceso import DialogoAcceso, DialogoPrimerIngreso, DialogoTotp
from consola.repositorio import EstadoNeon
from consola.ventana import VentanaPrincipal


def _entrar(url: str, prefijo: str) -> EstadoNeon:
    conexion = conectar(url)
    servicio = ServicioAcceso(conexion, cifrador_local())
    servicio.verificar_clave(os.environ[f"LAB_{prefijo}_USUARIO"], os.environ[f"LAB_{prefijo}_CLAVE"])
    servicio.verificar_totp(pyotp.TOTP(os.environ[f"LAB_{prefijo}_TOTP"]).now())
    cuenta = servicio.completar()
    return EstadoNeon(conexion, url, cuenta, servicio.sesion_id, servicio.cifrador)


def _guardar(app, widget, ruta: Path) -> None:
    widget.show()
    for _ in range(5):
        app.processEvents()
    widget.grab().save(str(ruta))
    print("  ", ruta.name)


def _ejecutar_sensor_contenciones() -> None:
    """El sensor (con su propio login) ejecuta lo aprobado, como en producción."""
    from sensor.servicio import Servicio
    url = os.environ["CHONTRY_DB_URL_SENSOR"]
    servicio = Servicio(lambda: conectar(url), os.environ["CHONTRY_SENSOR_ID"], cifrador_local())
    servicio.publicador.start()
    servicio._atender_contenciones()
    servicio.detener()


def main(carpeta: Path) -> int:
    cargar_env()
    carpeta.mkdir(parents=True, exist_ok=True)
    app = QApplication(sys.argv)
    app.setStyleSheet(tema.QSS)

    acceso = DialogoAcceso(True, lambda u, c: False)
    acceso.usuario.setText(os.environ["LAB_ADMIN_USUARIO"])
    acceso.clave.setText("••••••••••••••")
    _guardar(app, acceso, carpeta / "00_inicio_sesion.png")
    acceso.close()

    estado = _entrar(os.environ["CHONTRY_DB_URL"], "ADMIN")
    # Acciones reales para que las vistas muestren el flujo completo
    propuesta = next((c for c in estado.contenciones if c.estado == "propuesta"), None)
    if propuesta:
        estado.aprobar(propuesta.id)
        _ejecutar_sensor_contenciones()
    alerta = next((a for a in estado.alertas if a.estado == "nueva"), None)
    if alerta:
        estado.cambiar_estado_alerta(alerta.id, "en_revision")
    if not estado.lista_blanca:
        estado.agregar_lista_blanca("10.10.20.200", "CT-SCAN-001", "Escáner de vulnerabilidades autorizado de TI", 90)
    reportes = carpeta / "reportes"
    reportes.mkdir(exist_ok=True)
    from consola.vistas import ReportesVista
    ReportesVista(estado).generar_a(str(reportes / "alertas.html"), "alertas", "html",
                                    datetime.now().astimezone() - timedelta(days=1), datetime.now().astimezone())
    from sensor.servicio import Servicio  # noqa: F401 - (ya importado arriba si hubo contención)
    estado._aplicar(__import__("consola.repositorio", fromlist=["_leer_todo"])._leer_todo(estado._conexion,
                                                                                         estado.sesion_id))

    ventana = VentanaPrincipal(estado)
    ventana.resize(1480, 900)
    ventana.show()
    for indice, nombre in enumerate(ventana.SECCIONES):
        ventana.navegacion.setCurrentRow(indice)
        vista = ventana.vistas[indice]
        if hasattr(vista, "tabla") and vista.modelo.rowCount():
            vista.tabla.selectRow(0)
        if nombre == "Auditoría":
            vista._verificar()
        _guardar(app, ventana, carpeta / f"{indice + 1:02d}_{nombre.lower().replace('í', 'i').replace(' ', '_')}.png")
    estado.cerrar()
    ventana.close()

    analista = _entrar(os.environ["CHONTRY_DB_URL_ANALISTA"], "ANALISTA")
    ventana = VentanaPrincipal(analista)
    ventana.resize(1480, 900)
    ventana.navegacion.setCurrentRow(ventana.SECCIONES.index("Cuarentena"))
    vista = ventana.vistas[ventana.SECCIONES.index("Cuarentena")]
    if vista.modelo.rowCount():
        vista.tabla.selectRow(0)
    _guardar(app, ventana, carpeta / "20_analista_cuarentena.png")
    analista.cerrar()
    ventana.close()

    # Segundo factor y primer ingreso (con un usuario recién creado)
    conexion = conectar(os.environ["CHONTRY_DB_URL_ANALISTA"])
    servicio = ServicioAcceso(conexion, cifrador_local())
    servicio.verificar_clave(os.environ["LAB_ANALISTA_USUARIO"], os.environ["LAB_ANALISTA_CLAVE"])
    _guardar(app, DialogoTotp(servicio), carpeta / "21_segundo_factor.png")
    servicio.cuenta.debe_cambiar_clave = True
    servicio.cuenta.mfa_cifrado = None
    primer = DialogoPrimerIngreso(servicio)
    _guardar(app, primer, carpeta / "22_primer_ingreso_clave.png")
    primer.pasos.setCurrentIndex(1)
    _guardar(app, primer, carpeta / "23_primer_ingreso_qr.png")
    conexion.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else RAIZ / "capturas" / "consola"))
