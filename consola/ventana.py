"""Ventana principal de la consola."""
from datetime import datetime, timezone

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QListWidget, QMainWindow, QPushButton, QStackedWidget,
                               QVBoxLayout, QWidget)

from consola import tema
from consola.vistas import (ActivosVista, AlertasVista, AuditoriaVista, CuarentenaVista, ListaBlancaVista, PanelVista,
                            ReglasVista, ReportesVista, UsuariosVista)
from sensor import VERSION


class VentanaPrincipal(QMainWindow):
    cerrar_sesion = Signal()

    def __init__(self, estado):
        super().__init__()
        self.estado = estado
        self.setWindowTitle("ChonTry · Consola")
        self.resize(1480, 900)
        secciones = [("Panel", PanelVista), ("Alertas", AlertasVista), ("Cuarentena", CuarentenaVista)]
        if not estado.es_demo:
            secciones += [("Activos", ActivosVista)]
        secciones += [("Reglas", ReglasVista)]
        if not estado.es_demo:
            secciones += [("Lista blanca", ListaBlancaVista)]
        secciones += [("Auditoría", AuditoriaVista)]
        if not estado.es_demo:
            secciones += [("Reportes", ReportesVista)]
            if estado.es_admin:
                secciones += [("Usuarios", UsuariosVista)]
        self.SECCIONES = [nombre for nombre, _ in secciones]

        central = QWidget()
        raiz = QHBoxLayout(central)
        raiz.setContentsMargins(0, 0, 0, 0)
        raiz.setSpacing(0)
        raiz.addWidget(self._barra_lateral())
        derecha = QVBoxLayout()
        derecha.setContentsMargins(0, 0, 0, 0)
        derecha.setSpacing(0)
        derecha.addWidget(self._encabezado())
        self.aviso = QLabel("")
        self.aviso.setStyleSheet(f"background:#fff4e5; color:{tema.AVISO}; padding:8px 26px; border-bottom:1px solid #f3dcb5;")
        self.aviso.setVisible(False)
        derecha.addWidget(self.aviso)
        self.paginas = QStackedWidget()
        self.vistas = [clase(estado) for _, clase in secciones]
        for vista in self.vistas:
            self.paginas.addWidget(vista)
        derecha.addWidget(self.paginas, 1)
        raiz.addLayout(derecha, 1)
        self.setCentralWidget(central)

        self.navegacion.addItems(self.SECCIONES)
        self.navegacion.currentRowChanged.connect(self._cambiar_pagina)
        self.navegacion.setCurrentRow(0)
        self.statusBar().showMessage(
            "Modo demostración · datos simulados en memoria · no se envía nada a ningún switch" if estado.es_demo
            else f"Conectado a {estado.origen_catalogo} · "
                 f"{'TLS con certificado verificado' if estado.tls_verificado else 'conexión local sin TLS (solo laboratorio)'}"
                 " · sesión auditada")
        estado.cambio.connect(self.refrescar)
        self.refrescar()

    def _barra_lateral(self) -> QFrame:
        barra = QFrame()
        barra.setObjectName("pieNavegacion")
        barra.setFixedWidth(220)
        v = QVBoxLayout(barra)
        v.setContentsMargins(0, 18, 0, 14)
        v.setSpacing(0)
        marca = QLabel("Chon<span style='color:#3ecf8e'>Try</span>")
        marca.setStyleSheet("color:#ffffff; font-size:18pt; font-weight:700; padding-left:22px;")
        sub = QLabel("Seguridad de red interna")
        sub.setObjectName("pieNavegacion")
        sub.setStyleSheet("padding-left:22px; padding-bottom:14px;")
        v.addWidget(marca)
        v.addWidget(sub)
        self.navegacion = QListWidget()
        self.navegacion.setObjectName("navegacion")
        v.addWidget(self.navegacion, 1)
        pie = QLabel(f"v{VERSION} · LOS CHONTOS")
        pie.setObjectName("pieNavegacion")
        pie.setStyleSheet("padding-left:22px;")
        v.addWidget(pie)
        return barra

    def _encabezado(self) -> QFrame:
        barra = QFrame()
        barra.setObjectName("encabezado")
        h = QHBoxLayout(barra)
        h.setContentsMargins(26, 12, 20, 12)
        self.titulo_pagina = QLabel("")
        self.titulo_pagina.setStyleSheet(f"font-size:12pt; font-weight:600; color:{tema.MARINO};")
        h.addWidget(self.titulo_pagina)
        h.addStretch()
        self.insignia_sensor = QLabel()
        self.insignia_sensor.setObjectName("insignia")
        catalogo = QLabel(("Demostración" if self.estado.es_demo else self.estado.origen_catalogo))
        catalogo.setObjectName("insignia")
        usuario = QLabel(f"{self.estado.usuario} · {tema.ROLES.get(self.estado.rol, self.estado.rol)}")
        usuario.setObjectName("insignia")
        usuario.setStyleSheet(f"color:{tema.ACENTO_OSCURO}; font-weight:600; background:{tema.ACENTO_CLARO}; "
                              f"border-color:#bfe3d3;")
        salir = QPushButton("Cerrar sesión")
        salir.clicked.connect(self.cerrar_sesion.emit)
        for widget in (self.insignia_sensor, catalogo, usuario, salir):
            h.addWidget(widget)
        return barra

    def _cambiar_pagina(self, indice: int) -> None:
        if indice < 0:
            return
        self.paginas.setCurrentIndex(indice)
        self.titulo_pagina.setText(self.SECCIONES[indice])
        self.vistas[indice].refrescar()

    def _estado_sensor(self) -> str:
        verde, rojo, gris = tema.EXITO, tema.PELIGRO, tema.TEXTO_SUAVE
        if self.estado.es_demo:
            pps = self.estado.pps[-1] if self.estado.pps else 0
            return f"<span style='color:{verde}'>●</span> sensor simulado · {pps:,} pps"
        if not self.estado.sensores:
            return f"<span style='color:{gris}'>●</span> sin sensores registrados"
        partes = []
        for _, nombre, estado, _, _, segundos in self.estado.sensores:
            vivo = estado == "activo" and segundos is not None and segundos < 120
            color = verde if vivo else rojo
            texto = f"hace {int(segundos)} s" if segundos is not None and vivo else ("sin reporte" if estado != "detenido" else "detenido")
            partes.append(f"<span style='color:{color}'>●</span> {nombre} · {texto}")
        return " &nbsp; ".join(partes[:2])

    def refrescar(self) -> None:
        self.insignia_sensor.setText(self._estado_sensor())
        error = getattr(self.estado, "ultimo_error", None)
        self.aviso.setText(f"Sin conexión con la base de datos; se reintenta cada pocos segundos. {error or ''}")
        self.aviso.setVisible(bool(error))
        abiertas = sum(self.estado.abiertas_por_severidad().values())
        contadores = {"Alertas": abiertas, "Cuarentena": self.estado.en_cuarentena()}
        for i, nombre in enumerate(self.SECCIONES):
            numero = contadores.get(nombre)
            self.navegacion.item(i).setText(f"{nombre}  ({numero})" if numero else nombre)
        self.vistas[self.paginas.currentIndex()].refrescar()
