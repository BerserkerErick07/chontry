"""Diálogos de acceso: inicio de sesión, segundo factor y primer ingreso (cambio de clave + QR)."""
from __future__ import annotations

import os
import re

import qrcode
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QImage, QPainter, QPixmap
from PySide6.QtWidgets import (QDialog, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton,
                               QRadioButton, QStackedWidget, QVBoxLayout, QWidget, QButtonGroup, QComboBox)

from comun.validacion import EntradaInvalida
from consola import tema
from consola.acceso import AccesoDenegado, ServicioAcceso

_USUARIO = re.compile(r"[a-z0-9._-]{3,32}")


def imagen_qr(texto: str, tam: int = 220) -> QPixmap:
    """Dibuja el QR a partir de su matriz (sin depender de Pillow)."""
    qr = qrcode.QRCode(border=2, error_correction=qrcode.constants.ERROR_CORRECT_M)
    qr.add_data(texto)
    qr.make(fit=True)
    matriz = qr.get_matrix()
    n = len(matriz)
    escala = max(1, tam // n)
    imagen = QImage(n * escala, n * escala, QImage.Format_RGB32)
    imagen.fill(QColor("#ffffff"))
    pintor = QPainter(imagen)
    for y, fila in enumerate(matriz):
        for x, celda in enumerate(fila):
            if celda:
                pintor.fillRect(x * escala, y * escala, escala, escala, QColor(tema.MARINO))
    pintor.end()
    return QPixmap.fromImage(imagen)


def _banda(titulo: str, subtitulo: str) -> QFrame:
    banda = QFrame()
    banda.setObjectName("bandaAcceso")
    v = QVBoxLayout(banda)
    v.setContentsMargins(28, 22, 28, 20)
    marca = QLabel(f"Chon<span style='color:#3ecf8e'>Try</span>")
    marca.setObjectName("marcaClara")
    sub = QLabel(subtitulo)
    sub.setObjectName("submarcaClara")
    v.addWidget(marca)
    v.addWidget(sub)
    if titulo:
        t = QLabel(titulo)
        t.setStyleSheet("color:#ffffff; font-weight:600; font-size:11pt; margin-top:6px;")
        v.addWidget(t)
    return banda


def _error() -> QLabel:
    etiqueta = QLabel("")
    etiqueta.setObjectName("error")
    etiqueta.setWordWrap(True)
    return etiqueta


class DialogoAcceso(QDialog):
    """Inicio de sesión. `modo` queda en 'bd' o 'demo'."""

    def __init__(self, hay_bd: bool, al_entrar):
        super().__init__()
        self.setWindowTitle("ChonTry · Iniciar sesión")
        self.setFixedWidth(440)
        self._al_entrar = al_entrar
        self.modo = "bd" if hay_bd else "demo"
        raiz = QVBoxLayout(self)
        raiz.setContentsMargins(0, 0, 0, 0)
        raiz.setSpacing(0)
        raiz.addWidget(_banda("", "IDS/IPS agentless para amenazas internas · LOS CHONTOS"))
        cuerpo = QWidget()
        v = QVBoxLayout(cuerpo)
        v.setContentsMargins(28, 22, 28, 24)
        v.setSpacing(10)

        self.radio_bd = QRadioButton("Base de datos (operación real)")
        self.radio_demo = QRadioButton("Demostración (sin base de datos, datos simulados)")
        grupo = QButtonGroup(self)
        for radio in (self.radio_bd, self.radio_demo):
            grupo.addButton(radio)
            v.addWidget(radio)
        self.radio_bd.setEnabled(hay_bd)
        self.radio_bd.setChecked(hay_bd)
        self.radio_demo.setChecked(not hay_bd)
        if not hay_bd:
            aviso = QLabel("No hay CHONTRY_DB_URL configurada en este equipo: solo está disponible la demostración.")
            aviso.setObjectName("subtitulo")
            aviso.setWordWrap(True)
            v.addWidget(aviso)

        formulario = QFormLayout()
        formulario.setVerticalSpacing(10)
        self.usuario = QLineEdit()
        self.usuario.setMaxLength(32)
        self.usuario.setPlaceholderText("usuario")
        self.clave = QLineEdit()
        self.clave.setEchoMode(QLineEdit.Password)
        self.clave.setMaxLength(128)
        self.rol = QComboBox()
        for clave, nombre in (("admin", "Administrador"), ("analista", "Analista"), ("auditor", "Auditor")):
            self.rol.addItem(nombre, clave)
        formulario.addRow("Usuario", self.usuario)
        self.fila_clave = QLabel("Contraseña")
        formulario.addRow(self.fila_clave, self.clave)
        self.fila_rol = QLabel("Rol")
        formulario.addRow(self.fila_rol, self.rol)
        v.addLayout(formulario)
        self.error = _error()
        v.addWidget(self.error)
        self.boton = QPushButton("Iniciar sesión")
        self.boton.setObjectName("primario")
        self.boton.setDefault(True)
        self.boton.clicked.connect(self._entrar)
        v.addWidget(self.boton)
        raiz.addWidget(cuerpo)
        self.radio_bd.toggled.connect(self._actualizar)
        self._actualizar()

    def _actualizar(self, *_):
        bd = self.radio_bd.isChecked()
        self.modo = "bd" if bd else "demo"
        for w in (self.clave, self.fila_clave):
            w.setVisible(bd)
        for w in (self.rol, self.fila_rol):
            w.setVisible(not bd)

    def _entrar(self) -> None:
        usuario = self.usuario.text().strip().lower()
        if not _USUARIO.fullmatch(usuario):
            self.error.setText("Usuario inválido: 3 a 32 caracteres a-z, 0-9, punto, guion o guion bajo.")
            return
        if self.modo == "demo":
            self.accept()
            return
        self.boton.setEnabled(False)
        try:
            if self._al_entrar(usuario, self.clave.text()):
                self.accept()
        except (AccesoDenegado, EntradaInvalida) as exc:
            self.error.setText(str(exc))
        finally:
            self.clave.clear()
            self.boton.setEnabled(True)

    def datos_demo(self) -> tuple[str, str]:
        return self.usuario.text().strip().lower(), self.rol.currentData()


class DialogoTotp(QDialog):
    def __init__(self, servicio: ServicioAcceso):
        super().__init__()
        self.servicio = servicio
        self.setWindowTitle("ChonTry · Segundo factor")
        self.setFixedWidth(400)
        raiz = QVBoxLayout(self)
        raiz.setContentsMargins(0, 0, 0, 0)
        raiz.addWidget(_banda("Verificación en dos pasos", "Abra su app autenticadora"))
        cuerpo = QWidget()
        v = QVBoxLayout(cuerpo)
        v.setContentsMargins(28, 20, 28, 24)
        v.addWidget(QLabel("Escriba el código de 6 dígitos que muestra su aplicación (Google Authenticator, "
                           "Microsoft Authenticator, Aegis…)."))
        self.codigo = QLineEdit()
        self.codigo.setMaxLength(6)
        self.codigo.setPlaceholderText("000000")
        self.codigo.setAlignment(Qt.AlignCenter)
        self.codigo.setStyleSheet("font-size:18pt; letter-spacing:6px;")
        v.addWidget(self.codigo)
        self.error = _error()
        v.addWidget(self.error)
        boton = QPushButton("Verificar")
        boton.setObjectName("primario")
        boton.setDefault(True)
        boton.clicked.connect(self._verificar)
        v.addWidget(boton)
        raiz.addWidget(cuerpo)
        for etiqueta in cuerpo.findChildren(QLabel):
            etiqueta.setWordWrap(True)

    def _verificar(self) -> None:
        try:
            self.servicio.verificar_totp(self.codigo.text())
            self.accept()
        except AccesoDenegado as exc:
            self.error.setText(str(exc))
            self.codigo.clear()


class DialogoPrimerIngreso(QDialog):
    """Cambio obligatorio de contraseña y/o registro del segundo factor."""

    def __init__(self, servicio: ServicioAcceso):
        super().__init__()
        self.servicio = servicio
        self.setWindowTitle("ChonTry · Primer ingreso")
        self.setFixedWidth(480)
        raiz = QVBoxLayout(self)
        raiz.setContentsMargins(0, 0, 0, 0)
        raiz.addWidget(_banda("Configuración de su cuenta", servicio.cuenta.usuario))
        self.pasos = QStackedWidget()
        raiz.addWidget(self.pasos)
        self.secreto = None
        if servicio.requiere_cambio_clave():
            self.pasos.addWidget(self._paso_clave())
        if servicio.requiere_enrolar():
            self.pasos.addWidget(self._paso_totp())

    def _contenedor(self) -> tuple[QWidget, QVBoxLayout]:
        caja = QWidget()
        v = QVBoxLayout(caja)
        v.setContentsMargins(28, 20, 28, 24)
        v.setSpacing(10)
        return caja, v

    def _paso_clave(self) -> QWidget:
        caja, v = self._contenedor()
        explicacion = QLabel("Su contraseña es temporal. Elija una nueva de al menos 12 caracteres; una frase "
                             "larga es más segura y fácil de recordar que una palabra con símbolos.")
        explicacion.setWordWrap(True)
        v.addWidget(explicacion)
        formulario = QFormLayout()
        self.nueva = QLineEdit()
        self.nueva.setEchoMode(QLineEdit.Password)
        self.nueva.setMaxLength(128)
        self.confirmacion = QLineEdit()
        self.confirmacion.setEchoMode(QLineEdit.Password)
        self.confirmacion.setMaxLength(128)
        formulario.addRow("Nueva contraseña", self.nueva)
        formulario.addRow("Confirmación", self.confirmacion)
        v.addLayout(formulario)
        self.error_clave = _error()
        v.addWidget(self.error_clave)
        boton = QPushButton("Guardar contraseña")
        boton.setObjectName("primario")
        boton.clicked.connect(self._guardar_clave)
        v.addWidget(boton)
        return caja

    def _paso_totp(self) -> QWidget:
        caja, v = self._contenedor()
        explicacion = QLabel("Active la verificación en dos pasos: escanee el código con su app autenticadora "
                             "y escriba el código de 6 dígitos que aparece.")
        explicacion.setWordWrap(True)
        v.addWidget(explicacion)
        self.qr = QLabel()
        self.qr.setAlignment(Qt.AlignCenter)
        v.addWidget(self.qr)
        self.texto_secreto = QLabel()
        self.texto_secreto.setAlignment(Qt.AlignCenter)
        self.texto_secreto.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.texto_secreto.setObjectName("subtitulo")
        v.addWidget(self.texto_secreto)
        fila = QHBoxLayout()
        self.codigo = QLineEdit()
        self.codigo.setMaxLength(6)
        self.codigo.setPlaceholderText("000000")
        self.codigo.setAlignment(Qt.AlignCenter)
        fila.addWidget(self.codigo)
        boton = QPushButton("Activar")
        boton.setObjectName("primario")
        boton.clicked.connect(self._enrolar)
        fila.addWidget(boton)
        v.addLayout(fila)
        self.error_totp = _error()
        v.addWidget(self.error_totp)
        try:
            self.secreto, uri = self.servicio.nuevo_secreto_totp()
            self.qr.setPixmap(imagen_qr(uri))
            grupos = " ".join(self.secreto[i:i + 4] for i in range(0, len(self.secreto), 4))
            self.texto_secreto.setText(f"Clave manual: {grupos}")
        except AccesoDenegado as exc:
            self.error_totp.setText(str(exc))
            self.codigo.setEnabled(False)
            boton.setEnabled(False)
        return caja

    def _siguiente(self) -> None:
        if self.pasos.currentIndex() + 1 < self.pasos.count():
            self.pasos.setCurrentIndex(self.pasos.currentIndex() + 1)
        else:
            self.accept()

    def _guardar_clave(self) -> None:
        try:
            self.servicio.cambiar_clave(self.nueva.text(), self.confirmacion.text())
        except (EntradaInvalida, AccesoDenegado) as exc:
            self.error_clave.setText(str(exc))
            return
        finally:
            self.nueva.clear()
            self.confirmacion.clear()
        self._siguiente()

    def _enrolar(self) -> None:
        try:
            self.servicio.enrolar_totp(self.secreto, self.codigo.text())
        except (EntradaInvalida, AccesoDenegado) as exc:
            self.error_totp.setText(str(exc))
            return
        self._siguiente()


def hay_base_de_datos() -> bool:
    return bool(os.environ.get("CHONTRY_DB_URL"))
