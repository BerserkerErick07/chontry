"""Vistas de la consola. Funcionan con el backend real (repositorio.EstadoNeon) y con el
de demostración (estado.Estado), que exponen la misma interfaz."""
import json
from datetime import date, datetime, time, timedelta

from PySide6.QtCharts import QChart, QChartView, QLineSeries, QValueAxis
from PySide6.QtCore import QDate, QPointF, Qt
from PySide6.QtGui import QColor, QPainter, QPen
from PySide6.QtWidgets import (QCheckBox, QComboBox, QDateEdit, QDialog, QDialogButtonBox, QFileDialog, QFormLayout,
                               QFrame, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton,
                               QSpinBox, QSplitter, QVBoxLayout, QWidget)

from comun.validacion import EntradaInvalida, validar_interfaz_switch, validar_ip
from consola import tema
from consola.estado import CONTENCION_ACTIVA, ESTADOS_ABIERTOS, VLAN_CUARENTENA
from consola.widgets import (Columna, ModeloTabla, TarjetaKpi, accion_segura, color_severidad, crear_tabla,
                             seleccionar_por_id, titulo_vista)

DERECHA = Qt.AlignRight | Qt.AlignVCenter


def _hora(ts) -> str:
    if ts is None:
        return "—"
    if ts.tzinfo is not None:
        ts = ts.astimezone()
    return ts.strftime("%H:%M:%S") if ts.date() == date.today() else ts.strftime("%d/%m %H:%M")


def _severidad(alerta) -> str:
    return tema.NOMBRE_SEVERIDAD[alerta.severidad]


def _requiere_admin(boton: QPushButton, estado) -> None:
    """Deshabilita en la interfaz lo que el rol no permite. El control real está en la BD."""
    if not estado.es_admin:
        boton.setEnabled(False)
        boton.setToolTip("Requiere rol administrador")


def _requiere_operador(boton: QPushButton, estado) -> None:
    if not estado.puede_operar:
        boton.setEnabled(False)
        boton.setToolTip("El rol auditor es de solo lectura")


def _etiqueta_seccion(texto: str) -> QLabel:
    etiqueta = QLabel(texto)
    etiqueta.setObjectName("seccion")
    return etiqueta


def _vista_base(widget: QWidget, titulo: str, subtitulo: str) -> QVBoxLayout:
    disposicion = QVBoxLayout(widget)
    disposicion.setContentsMargins(26, 22, 26, 22)
    disposicion.setSpacing(12)
    disposicion.addWidget(titulo_vista(titulo, subtitulo))
    return disposicion


COLUMNAS_ALERTA = [
    Columna("#", lambda a: a.id, alineacion=DERECHA),
    Columna("Severidad", _severidad, lambda a: color_severidad(a.severidad)),
    Columna("Regla", lambda a: a.regla.codigo),
    Columna("Origen", lambda a: a.ip_origen),
    Columna("Descripción", lambda a: a.resumen),
    Columna("Eventos", lambda a: a.conteo, alineacion=DERECHA),
    Columna("Puntaje", lambda a: a.puntaje, alineacion=DERECHA),
    Columna("Estado", lambda a: tema.ESTADO_ALERTA[a.estado],
            lambda a: tema.TEXTO if a.estado in ESTADOS_ABIERTOS else tema.TEXTO_SUAVE),
    Columna("Última", lambda a: _hora(a.ultima)),
]


class _VistaConDetalle(QWidget):
    """Tabla + panel de detalle que conserva la fila seleccionada al refrescar."""
    modelo: ModeloTabla

    def _armar_tabla(self, columnas, estirar):
        self._seleccion = None
        self.modelo = ModeloTabla(columnas)
        self.tabla = crear_tabla(self.modelo, estirar=estirar)
        self.tabla.selectionModel().selectionChanged.connect(self._al_seleccionar)
        return self.tabla

    def _actual(self):
        filas = self.tabla.selectionModel().selectedRows()
        return self.modelo.fila(filas[0].row()) if filas else None

    def _al_seleccionar(self, *_):
        actual = self._actual()
        self._seleccion = _ident(actual)
        self._mostrar(actual)

    def _poner_filas(self, filas) -> None:
        seleccion = self._seleccion
        self.modelo.set_filas(filas)
        for i, fila in enumerate(self.modelo.filas()):
            if _ident(fila) == seleccion and seleccion is not None:
                self.tabla.selectRow(i)
                break
        self._seleccion = seleccion
        self._mostrar(self._actual())

    def _mostrar(self, objeto) -> None:
        raise NotImplementedError


def _ident(objeto):
    if objeto is None:
        return None
    if isinstance(objeto, tuple):
        return objeto[0]
    return getattr(objeto, "id", None) or getattr(objeto, "codigo", None)


def _caja_detalle(titulo: str) -> tuple[QFrame, QVBoxLayout]:
    caja = QFrame()
    caja.setObjectName("detalle")
    v = QVBoxLayout(caja)
    v.setContentsMargins(18, 16, 18, 16)
    v.setSpacing(8)
    v.addWidget(_etiqueta_seccion(titulo))
    return caja, v


# ---------------------------------------------------------------------- Panel
class PanelVista(QWidget):
    def __init__(self, estado):
        super().__init__()
        self.estado = estado
        disposicion = _vista_base(self, "Panel de monitoreo",
                                  "Amenazas internas detectadas en el tráfico del puerto espejo (SPAN).")
        fila = QHBoxLayout()
        fila.setSpacing(12)
        self.kpis = {
            "critica": TarjetaKpi("Críticas abiertas", tema.SEVERIDAD["critica"]),
            "alta": TarjetaKpi("Altas abiertas", tema.SEVERIDAD["alta"]),
            "media": TarjetaKpi("Medias abiertas", tema.SEVERIDAD["media"]),
            "cuarentena": TarjetaKpi("Hosts en cuarentena", tema.ACENTO),
            "pendientes": TarjetaKpi("Pendientes de aprobación", tema.MARINO),
        }
        for tarjeta in self.kpis.values():
            fila.addWidget(tarjeta)
        disposicion.addLayout(fila)

        centro = QHBoxLayout()
        centro.setSpacing(12)
        centro.addWidget(self._crear_grafico(), 3)
        caja, v = _caja_detalle("PRINCIPALES ORÍGENES")
        self.modelo_origenes = ModeloTabla([
            Columna("Host", lambda f: f[0]),
            Columna("Eventos", lambda f: f[1], alineacion=DERECHA),
            Columna("Máx.", lambda f: tema.NOMBRE_SEVERIDAD[f[2]], lambda f: color_severidad(f[2])),
        ])
        v.addWidget(crear_tabla(self.modelo_origenes, estirar=0))
        centro.addWidget(caja, 2)
        disposicion.addLayout(centro, 3)
        disposicion.addWidget(_etiqueta_seccion("ÚLTIMAS ALERTAS"))
        self.modelo_recientes = ModeloTabla(COLUMNAS_ALERTA)
        disposicion.addWidget(crear_tabla(self.modelo_recientes, estirar=4), 2)

    def _crear_grafico(self) -> QFrame:
        self.serie = QLineSeries()
        self.serie.setPen(QPen(QColor(tema.ACENTO), 2.5))
        grafico = QChart()
        grafico.addSeries(self.serie)
        grafico.legend().hide()
        grafico.setTitle("Tráfico observado en el SPAN (paquetes/s)")
        grafico.setTitleBrush(QColor(tema.MARINO))
        grafico.setBackgroundBrush(QColor(tema.PANEL))
        grafico.setBackgroundRoundness(0)
        self.eje_x = QValueAxis()
        self.eje_x.setRange(0, 120)
        self.eje_x.setLabelsVisible(False)
        self.eje_y = QValueAxis()
        self.eje_y.setLabelFormat("%d")
        for eje in (self.eje_x, self.eje_y):
            eje.setGridLineColor(QColor(tema.BORDE))
            eje.setLinePenColor(QColor(tema.BORDE))
            eje.setLabelsColor(QColor(tema.TEXTO_SUAVE))
        grafico.addAxis(self.eje_x, Qt.AlignBottom)
        grafico.addAxis(self.eje_y, Qt.AlignLeft)
        self.serie.attachAxis(self.eje_x)
        self.serie.attachAxis(self.eje_y)
        vista = QChartView(grafico)
        vista.setRenderHint(QPainter.Antialiasing)
        vista.setMinimumHeight(240)
        self.sin_datos = QLabel("Aún no hay métricas: el sensor las envía cada pocos segundos.")
        self.sin_datos.setObjectName("subtitulo")
        self.sin_datos.setAlignment(Qt.AlignCenter)
        caja = QFrame()
        caja.setObjectName("panel")
        v = QVBoxLayout(caja)
        v.addWidget(vista)
        v.addWidget(self.sin_datos)
        return caja

    def refrescar(self) -> None:
        conteo = self.estado.abiertas_por_severidad()
        for clave in ("critica", "alta", "media"):
            self.kpis[clave].fijar(conteo[clave])
        self.kpis["cuarentena"].fijar(self.estado.en_cuarentena())
        self.kpis["pendientes"].fijar(self.estado.pendientes())
        muestras = list(self.estado.pps)
        desplazamiento = 120 - len(muestras)
        self.serie.replace([QPointF(desplazamiento + i, v) for i, v in enumerate(muestras)])
        self.eje_y.setRange(0, max([100, *muestras]) * 1.2)
        self.eje_y.applyNiceNumbers()
        self.sin_datos.setVisible(not muestras)
        self.modelo_origenes.set_filas(self.estado.principales_origenes())
        self.modelo_recientes.set_filas(list(reversed(self.estado.alertas))[:8])


# -------------------------------------------------------------------- Alertas
class AlertasVista(_VistaConDetalle):
    def __init__(self, estado):
        super().__init__()
        self.estado = estado
        disposicion = _vista_base(self, "Alertas",
                                  "Detecciones agrupadas por origen y regla. Seleccione una alerta para ver el detalle.")
        filtros = QHBoxLayout()
        self.filtro_estado = QComboBox()
        self.filtro_estado.addItem("Abiertas", ESTADOS_ABIERTOS)
        self.filtro_estado.addItem("Todas", None)
        for clave, nombre in tema.ESTADO_ALERTA.items():
            self.filtro_estado.addItem(nombre, (clave,))
        self.filtro_severidad = QComboBox()
        self.filtro_severidad.addItem("Todas las severidades", None)
        for clave in ("critica", "alta", "media", "baja"):
            self.filtro_severidad.addItem(tema.NOMBRE_SEVERIDAD[clave], clave)
        for combo in (self.filtro_estado, self.filtro_severidad):
            combo.currentIndexChanged.connect(self.refrescar)
            filtros.addWidget(combo)
        filtros.addStretch()
        disposicion.addLayout(filtros)
        divisor = QSplitter()
        divisor.addWidget(self._armar_tabla(COLUMNAS_ALERTA, 4))
        divisor.addWidget(self._crear_detalle())
        divisor.setSizes([820, 400])
        disposicion.addWidget(divisor, 1)

    def _crear_detalle(self) -> QFrame:
        caja, v = _caja_detalle("DETALLE")
        formulario = QFormLayout()
        formulario.setVerticalSpacing(8)
        self.campos = {}
        for clave, nombre in [("regla", "Regla"), ("mitre", "MITRE ATT&CK"), ("severidad", "Severidad"),
                              ("origen", "Origen"), ("destinos", "Destinos"), ("puertos", "Puertos"),
                              ("eventos", "Eventos"), ("ventana", "Ventana"), ("estado", "Estado")]:
            campo = QLabel("—")
            campo.setWordWrap(True)
            campo.setTextInteractionFlags(Qt.TextSelectableByMouse)
            self.campos[clave] = campo
            formulario.addRow(QLabel(nombre + ":"), campo)
        v.addLayout(formulario)
        v.addStretch()
        self.btn_revision = QPushButton("Marcar en revisión")
        self.btn_falso = QPushButton("Falso positivo")
        self.btn_cerrar = QPushButton("Cerrar alerta")
        self.btn_evidencia = QPushButton("Exportar evidencia (.pcap)")
        self.btn_revision.clicked.connect(self._en_revision)
        self.btn_falso.clicked.connect(self._falso_positivo)
        self.btn_cerrar.clicked.connect(self._cerrar)
        self.btn_evidencia.clicked.connect(self._evidencia)
        for boton in (self.btn_revision, self.btn_falso, self.btn_cerrar, self.btn_evidencia):
            v.addWidget(boton)
        self.btn_evidencia.setVisible(not self.estado.es_demo)
        return caja

    def _mostrar(self, alerta) -> None:
        abierta = alerta is not None and alerta.estado not in ("cerrada", "falso_positivo")
        for boton in (self.btn_revision, self.btn_falso, self.btn_cerrar):
            boton.setEnabled(abierta)
            _requiere_operador(boton, self.estado)
        self.btn_evidencia.setEnabled(alerta is not None and bool(getattr(alerta, "uid", None)))
        if alerta is None:
            for campo in self.campos.values():
                campo.setText("—")
            self.campos["severidad"].setStyleSheet("")
            return
        puertos = sorted(alerta.puertos)
        texto_puertos = ", ".join(map(str, puertos[:14])) + (f" … (+{len(puertos) - 14})" if len(puertos) > 14 else "")
        destinos = sorted(alerta.destinos)
        texto_destinos = ", ".join(destinos[:4]) + (f" … (+{len(destinos) - 4})" if len(destinos) > 4 else "")
        self.campos["regla"].setText(f"{alerta.regla.codigo} — {alerta.regla.nombre}")
        self.campos["mitre"].setText(alerta.regla.mitre or "—")
        self.campos["severidad"].setText(f"{_severidad(alerta)} · puntaje {alerta.puntaje}")
        self.campos["severidad"].setStyleSheet(f"color: {color_severidad(alerta.severidad)}; font-weight: 600;")
        self.campos["origen"].setText(f"{alerta.ip_origen}  ({alerta.mac_origen})")
        self.campos["destinos"].setText(texto_destinos or "—")
        self.campos["puertos"].setText(texto_puertos or "—")
        self.campos["eventos"].setText(str(alerta.conteo))
        self.campos["ventana"].setText(f"{_hora(alerta.primera)} → {_hora(alerta.ultima)}")
        self.campos["estado"].setText(tema.ESTADO_ALERTA[alerta.estado])

    @accion_segura
    def _en_revision(self):
        self.estado.cambiar_estado_alerta(self._actual().id, "en_revision")

    @accion_segura
    def _falso_positivo(self):
        self.estado.cambiar_estado_alerta(self._actual().id, "falso_positivo")

    @accion_segura
    def _cerrar(self):
        self.estado.cambiar_estado_alerta(self._actual().id, "cerrada")

    @accion_segura
    def _evidencia(self):
        alerta = self._actual()
        evidencias = [contenido for tipo, contenido in self.estado.evidencias(alerta) if tipo == "pcap"]
        if not evidencias:
            QMessageBox.information(self, "Evidencia", "Esta alerta no tiene evidencia de paquetes.")
            return
        ruta, _ = QFileDialog.getSaveFileName(self, "Guardar evidencia", f"alerta_{alerta.id}.pcap",
                                              "Captura de paquetes (*.pcap)")
        if ruta:
            with open(ruta, "wb") as archivo:
                archivo.write(evidencias[0])
            QMessageBox.information(self, "Evidencia", "Evidencia descifrada, verificada con SHA-256 y guardada. "
                                                       "Se puede abrir con Wireshark.")

    def refrescar(self, *_):
        estados = self.filtro_estado.currentData()
        severidad = self.filtro_severidad.currentData()
        self._poner_filas([a for a in reversed(self.estado.alertas)
                           if (estados is None or a.estado in estados) and (severidad is None or a.severidad == severidad)])


# ----------------------------------------------------------------- Cuarentena
class DialogoContencion(QDialog):
    """Contención manual con validación positiva en cada campo (ASVS V5)."""

    def __init__(self, estado, padre=None):
        super().__init__(padre)
        self.estado = estado
        self.setWindowTitle("Proponer contención manual")
        self.setMinimumWidth(480)
        v = QVBoxLayout(self)
        v.setContentsMargins(22, 20, 22, 20)
        aviso = QLabel("La propuesta queda pendiente hasta que un administrador la apruebe.")
        aviso.setObjectName("subtitulo")
        aviso.setWordWrap(True)
        v.addWidget(aviso)
        formulario = QFormLayout()
        self.ip = QLineEdit()
        self.ip.setPlaceholderText("10.10.20.45")
        self.ip.setMaxLength(45)
        self.puerto = QLineEdit()
        self.puerto.setPlaceholderText("Gi1/0/12 (vacío = el del inventario)" if not estado.es_demo else "Gi1/0/12")
        self.puerto.setMaxLength(40)
        self.vlan = QSpinBox()
        self.vlan.setRange(1, 4094)
        self.vlan.setValue(VLAN_CUARENTENA)
        self.motivo = QLineEdit()
        self.motivo.setMaxLength(300)
        self.motivo.setPlaceholderText("Ej.: escaneo reportado por el área de TI")
        self.error = QLabel("")
        self.error.setObjectName("error")
        self.error.setWordWrap(True)
        formulario.addRow("IP del host:", self.ip)
        formulario.addRow("Puerto del switch:", self.puerto)
        formulario.addRow("VLAN destino:", self.vlan)
        formulario.addRow("Motivo:", self.motivo)
        v.addLayout(formulario)
        v.addWidget(self.error)
        botones = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        botones.button(QDialogButtonBox.Ok).setText("Proponer")
        botones.button(QDialogButtonBox.Ok).setObjectName("primario")
        botones.button(QDialogButtonBox.Cancel).setText("Cancelar")
        botones.accepted.connect(self._aceptar)
        botones.rejected.connect(self.reject)
        v.addWidget(botones)
        self.ip.textChanged.connect(lambda t: self._marcar(self.ip, validar_ip, t))
        self.puerto.textChanged.connect(lambda t: self._marcar(self.puerto, validar_interfaz_switch, t))

    @staticmethod
    def _marcar(campo: QLineEdit, validador, texto: str) -> None:
        try:
            validador(texto.strip())
            invalido = False
        except EntradaInvalida:
            invalido = bool(texto)
        campo.setProperty("invalido", invalido)
        campo.style().unpolish(campo)
        campo.style().polish(campo)

    def _aceptar(self) -> None:
        try:
            self.estado.proponer_manual(self.ip.text(), self.puerto.text(), self.vlan.value(), self.motivo.text())
        except EntradaInvalida as exc:
            self.error.setText(str(exc))
            return
        except Exception as exc:  # noqa: BLE001 - mensaje genérico, detalle al log
            from comun.errores import manejar_error
            self.error.setText(manejar_error(exc, "proponer contención"))
            return
        self.accept()


class CuarentenaVista(_VistaConDetalle):
    def __init__(self, estado):
        super().__init__()
        self.estado = estado
        disposicion = _vista_base(
            self, "Cuarentena",
            f"Hosts aislados en la VLAN de cuarentena. Las propuestas requieren aprobación de un administrador; "
            f"las automáticas se liberan solas al vencer el TTL ({int(estado.ttl.total_seconds() // 60)} min).")
        barra = QHBoxLayout()
        self.filtro = QComboBox()
        self.filtro.addItem("Activas", CONTENCION_ACTIVA)
        self.filtro.addItem("Todas", None)
        self.filtro.currentIndexChanged.connect(self.refrescar)
        barra.addWidget(self.filtro)
        barra.addStretch()
        self.boton_manual = QPushButton("Contención manual…")
        self.boton_manual.clicked.connect(self._manual)
        _requiere_operador(self.boton_manual, estado)
        barra.addWidget(self.boton_manual)
        disposicion.addLayout(barra)
        divisor = QSplitter()
        divisor.addWidget(self._armar_tabla([
            Columna("#", lambda c: c.id, alineacion=DERECHA),
            Columna("Host", lambda c: c.ip),
            Columna("Puerto", lambda c: f"{c.switch} {c.puerto}"),
            Columna("VLAN", lambda c: f"{c.vlan_origen} → {c.vlan_destino}"),
            Columna("Modo", lambda c: "Automática" if c.modo == "automatica" else "Manual"),
            Columna("Estado", lambda c: tema.ESTADO_CONTENCION[c.estado], lambda c: tema.COLOR_CONTENCION[c.estado]),
            Columna("Motivo", lambda c: c.motivo),
            Columna("Expira", lambda c: _hora(c.expira_en) if c.estado == "aplicada" else "—"),
        ], 6))
        divisor.addWidget(self._crear_detalle())
        divisor.setSizes([800, 420])
        disposicion.addWidget(divisor, 1)

    def _crear_detalle(self) -> QFrame:
        caja, v = _caja_detalle("COMANDOS PARA EL SWITCH")
        nota = QLabel("Generados con plantilla fija y valores validados. Los ejecuta el sensor, que tiene las "
                      "credenciales del switch.")
        nota.setObjectName("subtitulo")
        nota.setWordWrap(True)
        v.addWidget(nota)
        self.comandos = QPlainTextEdit()
        self.comandos.setObjectName("comandos")
        self.comandos.setReadOnly(True)
        self.comandos.setMaximumHeight(100)
        v.addWidget(self.comandos)
        self.info = QLabel("—")
        self.info.setWordWrap(True)
        self.info.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v.addWidget(self.info)
        v.addStretch()
        self.btn_aprobar = QPushButton("Aprobar y aplicar")
        self.btn_aprobar.setObjectName("primario")
        self.btn_rechazar = QPushButton("Rechazar")
        self.btn_revertir = QPushButton("Liberar host")
        self.btn_revertir.setObjectName("peligro")
        self.btn_aprobar.clicked.connect(self._aprobar)
        self.btn_rechazar.clicked.connect(self._rechazar)
        self.btn_revertir.clicked.connect(self._revertir)
        for boton in (self.btn_aprobar, self.btn_rechazar, self.btn_revertir):
            v.addWidget(boton)
        return caja

    def _mostrar(self, c) -> None:
        self.btn_aprobar.setEnabled(c is not None and c.estado == "propuesta")
        self.btn_rechazar.setEnabled(c is not None and c.estado == "propuesta")
        self.btn_revertir.setEnabled(c is not None and c.estado == "aplicada")
        for boton in (self.btn_aprobar, self.btn_rechazar, self.btn_revertir):
            _requiere_admin(boton, self.estado)
        if c is None:
            self.comandos.setPlainText("")
            self.info.setText("Seleccione una contención.")
            return
        self.comandos.setPlainText("\n".join(c.comandos))
        lineas = [f"<b>Host:</b> {c.ip} ({c.mac})",
                  f"<b>Solicitada por:</b> {c.solicitado_por} · {_hora(c.creada)}"]
        if c.aprobado_por:
            lineas.append(f"<b>Aprobada por:</b> {c.aprobado_por}")
        if c.alerta_id:
            lineas.append(f"<b>Alerta:</b> #{c.alerta_id}")
        if getattr(c, "salida", None):
            primera = c.salida.splitlines()[0][:90]
            lineas.append(f"<b>Resultado en el switch:</b> {primera}")
        if getattr(c, "error", None):
            lineas.append(f"<span style='color:{tema.PELIGRO}'><b>Error:</b> {c.error[:120]}</span>")
        self.info.setText("<br>".join(lineas))

    @accion_segura
    def _manual(self):
        DialogoContencion(self.estado, self).exec()

    @accion_segura
    def _aprobar(self):
        self.estado.aprobar(self._actual().id)

    @accion_segura
    def _rechazar(self):
        self.estado.rechazar(self._actual().id)

    @accion_segura
    def _revertir(self):
        c = self._actual()
        if QMessageBox.question(self, "Liberar host", f"¿Devolver {c.ip} a la VLAN {c.vlan_origen}?") == QMessageBox.Yes:
            self.estado.revertir(c.id)

    def refrescar(self, *_):
        estados = self.filtro.currentData()
        self._poner_filas([c for c in reversed(self.estado.contenciones) if estados is None or c.estado in estados])


# -------------------------------------------------------------------- Activos
class ActivosVista(_VistaConDetalle):
    def __init__(self, estado):
        super().__init__()
        self.estado = estado
        disposicion = _vista_base(self, "Activos de la red",
                                  "Inventario construido por el sensor a partir del tráfico. Un activo protegido "
                                  "(gateway, DNS, controlador de dominio) nunca se aísla automáticamente.")
        barra = QHBoxLayout()
        self.buscar = QLineEdit()
        self.buscar.setPlaceholderText("Buscar por IP, MAC o nombre…")
        self.buscar.setMaxLength(60)
        self.buscar.textChanged.connect(self.refrescar)
        barra.addWidget(self.buscar, 1)
        self.solo_protegidos = QCheckBox("Solo protegidos")
        self.solo_protegidos.toggled.connect(self.refrescar)
        barra.addWidget(self.solo_protegidos)
        disposicion.addLayout(barra)
        divisor = QSplitter()
        divisor.addWidget(self._armar_tabla([
            Columna("IP", lambda a: a[1]),
            Columna("MAC", lambda a: a[2]),
            Columna("Nombre", lambda a: a[3] or ""),
            Columna("Segmento", lambda a: a[4] or ""),
            Columna("Switch / puerto", lambda a: f"{a[5] or '—'} {a[6] or ''}"),
            Columna("VLAN", lambda a: a[7] or a[13] or "", alineacion=DERECHA),
            Columna("Criticidad", lambda a: a[8], alineacion=DERECHA),
            Columna("Protegido", lambda a: "Sí" if a[9] else "", lambda a: tema.ACENTO if a[9] else None),
            Columna("Visto", lambda a: _hora(a[11])),
        ], 2))
        divisor.addWidget(self._crear_detalle())
        divisor.setSizes([820, 400])
        disposicion.addWidget(divisor, 1)

    def _crear_detalle(self) -> QFrame:
        caja, v = _caja_detalle("EDITAR ACTIVO")
        formulario = QFormLayout()
        self.nombre = QLineEdit()
        self.nombre.setMaxLength(63)
        self.notas = QLineEdit()
        self.notas.setMaxLength(500)
        self.puerto = QLineEdit()
        self.puerto.setMaxLength(40)
        self.vlan = QSpinBox()
        self.vlan.setRange(0, 4094)
        self.vlan.setSpecialValueText("—")
        self.criticidad = QSpinBox()
        self.criticidad.setRange(1, 5)
        self.protegido = QCheckBox("No aislar nunca (activo protegido)")
        formulario.addRow("Nombre", self.nombre)
        formulario.addRow("Notas", self.notas)
        formulario.addRow("Puerto del switch", self.puerto)
        formulario.addRow("VLAN actual", self.vlan)
        formulario.addRow("Criticidad (1-5)", self.criticidad)
        v.addLayout(formulario)
        v.addWidget(self.protegido)
        nota = QLabel("Puerto, VLAN, criticidad y protección solo los cambia un administrador.")
        nota.setObjectName("subtitulo")
        nota.setWordWrap(True)
        v.addWidget(nota)
        v.addStretch()
        self.guardar = QPushButton("Guardar cambios")
        self.guardar.setObjectName("primario")
        self.guardar.clicked.connect(self._guardar)
        v.addWidget(self.guardar)
        for w in (self.puerto, self.vlan, self.criticidad, self.protegido):
            w.setEnabled(self.estado.es_admin)
        return caja

    def _mostrar(self, a) -> None:
        self.guardar.setEnabled(a is not None)
        _requiere_operador(self.guardar, self.estado)
        if a is None or self.nombre.hasFocus() or self.notas.hasFocus() or self.puerto.hasFocus():
            return
        self.nombre.setText(a[3] or "")
        self.notas.setText(a[10] or "")
        self.puerto.setText(a[6] or "")
        self.vlan.setValue(a[7] or 0)
        self.criticidad.setValue(a[8])
        self.protegido.setChecked(bool(a[9]))

    @accion_segura
    def _guardar(self):
        a = self._actual()
        if self.estado.es_admin:
            self.estado.actualizar_activo(a[0], self.nombre.text(), self.notas.text(), self.criticidad.value(),
                                          self.protegido.isChecked(), self.puerto.text().strip() or None,
                                          self.vlan.value() or None)
        else:
            self.estado.actualizar_activo(a[0], self.nombre.text(), self.notas.text())

    def refrescar(self, *_):
        texto = self.buscar.text().strip().lower()
        self._poner_filas([a for a in self.estado.activos
                           if (not self.solo_protegidos.isChecked() or a[9])
                           and (not texto or texto in f"{a[1]} {a[2]} {a[3] or ''}".lower())])


# --------------------------------------------------------------------- Reglas
class ReglasVista(_VistaConDetalle):
    ACCIONES = {"alertar": "Solo alertar", "proponer_contencion": "Proponer contención", "contener": "Contener"}

    def __init__(self, estado):
        super().__init__()
        self.estado = estado
        disposicion = _vista_base(self, "Reglas de detección",
                                  f"Catálogo cargado desde: {estado.origen_catalogo}. Los umbrales se ajustan con la "
                                  "herramienta de administración; aquí un administrador puede activar o desactivar reglas.")
        disposicion.addWidget(self._armar_tabla([
            Columna("Código", lambda r: r.codigo),
            Columna("Nombre", lambda r: r.nombre),
            Columna("Severidad", lambda r: tema.NOMBRE_SEVERIDAD[r.severidad], lambda r: color_severidad(r.severidad)),
            Columna("Respuesta", lambda r: self.ACCIONES.get(r.accion, r.accion)),
            Columna("MITRE", lambda r: r.mitre),
            Columna("Activa", lambda r: "Sí" if r.habilitada else "No",
                    lambda r: tema.ACENTO if r.habilitada else tema.PELIGRO),
            Columna("Umbral", lambda r: json.dumps(r.parametros, ensure_ascii=False)),
        ], 6), 1)
        barra = QHBoxLayout()
        barra.addStretch()
        self.boton = QPushButton("Activar / desactivar regla")
        self.boton.clicked.connect(self._alternar)
        barra.addWidget(self.boton)
        self.boton.setVisible(not estado.es_demo)
        disposicion.addLayout(barra)

    def _mostrar(self, regla) -> None:
        self.boton.setEnabled(regla is not None)
        _requiere_admin(self.boton, self.estado)

    @accion_segura
    def _alternar(self):
        regla = self._actual()
        self.estado.habilitar_regla(regla.codigo, not regla.habilitada)

    def refrescar(self, *_):
        self._poner_filas(list(self.estado.reglas.values()))


# ---------------------------------------------------------------- Lista blanca
class DialogoListaBlanca(QDialog):
    def __init__(self, estado, padre=None):
        super().__init__(padre)
        self.estado = estado
        self.setWindowTitle("Agregar excepción a la lista blanca")
        self.setMinimumWidth(480)
        v = QVBoxLayout(self)
        v.setContentsMargins(22, 20, 22, 20)
        aviso = QLabel("Use excepciones solo para herramientas autorizadas (por ejemplo, el escáner de "
                       "vulnerabilidades del área de TI). Toda excepción queda auditada.")
        aviso.setObjectName("subtitulo")
        aviso.setWordWrap(True)
        v.addWidget(aviso)
        formulario = QFormLayout()
        self.valor = QLineEdit()
        self.valor.setPlaceholderText("10.10.20.200, 10.10.40.0/24 o aa:bb:cc:dd:ee:ff")
        self.valor.setMaxLength(43)
        self.regla = QComboBox()
        self.regla.addItem("Todas las reglas", None)
        for codigo, regla in estado.reglas.items():
            self.regla.addItem(f"{codigo} — {regla.nombre}", codigo)
        self.motivo = QLineEdit()
        self.motivo.setMaxLength(300)
        self.dias = QSpinBox()
        self.dias.setRange(0, 365)
        self.dias.setValue(30)
        self.dias.setSpecialValueText("Sin vencimiento")
        formulario.addRow("IP, red o MAC", self.valor)
        formulario.addRow("Regla", self.regla)
        formulario.addRow("Justificación", self.motivo)
        formulario.addRow("Vigencia (días)", self.dias)
        v.addLayout(formulario)
        self.error = QLabel("")
        self.error.setObjectName("error")
        self.error.setWordWrap(True)
        v.addWidget(self.error)
        botones = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        botones.button(QDialogButtonBox.Ok).setText("Agregar")
        botones.button(QDialogButtonBox.Ok).setObjectName("primario")
        botones.button(QDialogButtonBox.Cancel).setText("Cancelar")
        botones.accepted.connect(self._aceptar)
        botones.rejected.connect(self.reject)
        v.addWidget(botones)

    def _aceptar(self):
        try:
            self.estado.agregar_lista_blanca(self.valor.text(), self.regla.currentData(), self.motivo.text(),
                                             self.dias.value())
        except EntradaInvalida as exc:
            self.error.setText(str(exc))
            return
        self.accept()


class ListaBlancaVista(_VistaConDetalle):
    def __init__(self, estado):
        super().__init__()
        self.estado = estado
        disposicion = _vista_base(self, "Lista blanca",
                                  "Excepciones vigentes: el sensor no genera alertas para estos orígenes. "
                                  "Solo un administrador puede agregarlas o quitarlas.")
        disposicion.addWidget(self._armar_tabla([
            Columna("Red / IP", lambda f: f[1] or "—"),
            Columna("MAC", lambda f: f[2] or "—"),
            Columna("Regla", lambda f: f[3]),
            Columna("Justificación", lambda f: f[4]),
            Columna("Creada por", lambda f: f[5] or "—"),
            Columna("Vence", lambda f: _hora(f[7]) if f[7] else "Nunca"),
        ], 3), 1)
        barra = QHBoxLayout()
        barra.addStretch()
        self.agregar = QPushButton("Agregar excepción…")
        self.agregar.setObjectName("primario")
        self.quitar = QPushButton("Quitar")
        self.quitar.setObjectName("peligro")
        self.agregar.clicked.connect(self._agregar)
        self.quitar.clicked.connect(self._quitar)
        _requiere_admin(self.agregar, estado)
        barra.addWidget(self.quitar)
        barra.addWidget(self.agregar)
        disposicion.addLayout(barra)

    def _mostrar(self, fila) -> None:
        self.quitar.setEnabled(fila is not None)
        _requiere_admin(self.quitar, self.estado)

    @accion_segura
    def _agregar(self):
        DialogoListaBlanca(self.estado, self).exec()

    @accion_segura
    def _quitar(self):
        fila = self._actual()
        if QMessageBox.question(self, "Quitar excepción", "¿Quitar esta excepción de la lista blanca?") == QMessageBox.Yes:
            self.estado.quitar_lista_blanca(fila[0])

    def refrescar(self, *_):
        self._poner_filas(self.estado.lista_blanca)


# ------------------------------------------------------------------ Auditoría
class AuditoriaVista(QWidget):
    def __init__(self, estado):
        super().__init__()
        self.estado = estado
        disposicion = _vista_base(self, "Auditoría",
                                  "Registro de solo anexado: cada entrada guarda el hash SHA-256 de la anterior, así "
                                  "que cualquier modificación o borrado rompe la cadena.")
        barra = QHBoxLayout()
        boton_verificar = QPushButton("Verificar integridad")
        boton_verificar.setObjectName("primario")
        boton_verificar.clicked.connect(self._verificar)
        self.boton_alterar = QPushButton("Demostración: alterar un registro")
        self.boton_alterar.setObjectName("peligro")
        self.boton_alterar.clicked.connect(self._alterar)
        self.boton_alterar.setVisible(estado.es_demo)
        _requiere_admin(self.boton_alterar, estado)
        self.resultado = QLabel("")
        barra.addWidget(boton_verificar)
        barra.addWidget(self.boton_alterar)
        barra.addSpacing(12)
        barra.addWidget(self.resultado, 1)
        disposicion.addLayout(barra)
        self.modelo = ModeloTabla([
            Columna("#", lambda e: e.id, alineacion=DERECHA),
            Columna("Hora", lambda e: _hora(e.ts)),
            Columna("Actor", lambda e: e.actor),
            Columna("Acción", lambda e: e.accion),
            Columna("Entidad", lambda e: f"{e.entidad} #{e.entidad_id}"),
            Columna("Detalle", lambda e: json.dumps(e.detalle, ensure_ascii=False, default=str)[:160]),
            Columna("Hash", lambda e: e.hash.hex()[:16] + "…", lambda e: tema.TEXTO_SUAVE),
        ])
        disposicion.addWidget(crear_tabla(self.modelo, estirar=5), 1)

    @accion_segura
    def _verificar(self):
        rotos = self.estado.verificar_auditoria()
        if rotos:
            self.resultado.setText(f"✖ Cadena rota en los registros {', '.join(map(str, rotos[:10]))}: hubo una "
                                   "modificación o un borrado.")
            self.resultado.setStyleSheet(f"color: {tema.PELIGRO}; font-weight: 600;")
        else:
            self.resultado.setText("✔ Cadena íntegra: ningún registro fue modificado ni borrado.")
            self.resultado.setStyleSheet(f"color: {tema.EXITO}; font-weight: 600;")

    @accion_segura
    def _alterar(self):
        identificador = self.estado.alterar_registro_demo()
        self.resultado.setText(f"Se modificó a escondidas el registro #{identificador}. Pulse «Verificar integridad»."
                               if identificador else "Aún no hay suficientes registros.")
        self.resultado.setStyleSheet(f"color: {tema.AVISO};")

    def refrescar(self, *_):
        self.modelo.set_filas(list(reversed(self.estado.auditoria))[:300])


# ------------------------------------------------------------------- Reportes
class ReportesVista(QWidget):
    TIPOS = {"alertas": "Alertas", "contenciones": "Contenciones", "auditoria": "Auditoría"}

    def __init__(self, estado):
        super().__init__()
        self.estado = estado
        disposicion = _vista_base(self, "Reportes",
                                  "Exporte alertas, contenciones o auditoría. Cada reporte queda registrado con su "
                                  "SHA-256 y el último hash de la auditoría como ancla de integridad.")
        caja, v = _caja_detalle("NUEVO REPORTE")
        fila = QHBoxLayout()
        self.tipo = QComboBox()
        for clave, nombre in self.TIPOS.items():
            self.tipo.addItem(nombre, clave)
        self.formato = QComboBox()
        self.formato.addItem("HTML (para leer)", "html")
        self.formato.addItem("CSV (para Excel)", "csv")
        self.desde = QDateEdit(QDate.currentDate().addDays(-7))
        self.hasta = QDateEdit(QDate.currentDate())
        for fecha in (self.desde, self.hasta):
            fecha.setCalendarPopup(True)
            fecha.setDisplayFormat("dd/MM/yyyy")
        for etiqueta, widget in (("Tipo", self.tipo), ("Formato", self.formato), ("Desde", self.desde),
                                 ("Hasta", self.hasta)):
            fila.addWidget(QLabel(etiqueta))
            fila.addWidget(widget)
        fila.addStretch()
        boton = QPushButton("Generar y guardar…")
        boton.setObjectName("primario")
        boton.clicked.connect(self._generar)
        fila.addWidget(boton)
        v.addLayout(fila)
        self.resultado = QLabel("")
        self.resultado.setWordWrap(True)
        self.resultado.setTextInteractionFlags(Qt.TextSelectableByMouse)
        v.addWidget(self.resultado)
        disposicion.addWidget(caja)
        disposicion.addWidget(_etiqueta_seccion("REPORTES GENERADOS"))
        self.modelo = ModeloTabla([
            Columna("#", lambda r: r[0], alineacion=DERECHA),
            Columna("Tipo", lambda r: self.TIPOS.get(r[1], r[1])),
            Columna("Formato", lambda r: r[2].upper()),
            Columna("Periodo", lambda r: f"{_hora(r[3])} → {_hora(r[4])}"),
            Columna("Generado por", lambda r: r[5]),
            Columna("Fecha", lambda r: _hora(r[6])),
            Columna("SHA-256", lambda r: r[7], lambda r: tema.TEXTO_SUAVE),
        ])
        disposicion.addWidget(crear_tabla(self.modelo, estirar=6), 1)

    def generar_a(self, ruta: str, tipo: str, formato: str, desde: datetime, hasta: datetime) -> str:
        contenido, resumen = self.estado.generar_reporte(tipo, desde, hasta, formato)
        with open(ruta, "wb") as archivo:
            archivo.write(contenido)
        return resumen

    @accion_segura
    def _generar(self):
        tipo, formato = self.tipo.currentData(), self.formato.currentData()
        desde = datetime.combine(self.desde.date().toPython(), time.min).astimezone()
        hasta = datetime.combine(self.hasta.date().toPython(), time.max).astimezone()
        ruta, _ = QFileDialog.getSaveFileName(self, "Guardar reporte", f"chontry_{tipo}_{date.today():%Y%m%d}.{formato}",
                                              f"{formato.upper()} (*.{formato})")
        if not ruta:
            return
        resumen = self.generar_a(ruta, tipo, formato, desde, hasta)
        self.resultado.setText(f"✔ Reporte guardado en {ruta}<br>SHA-256: <code>{resumen}</code>")

    def refrescar(self, *_):
        self.modelo.set_filas(self.estado.reportes)


# ------------------------------------------------------------------- Usuarios
class UsuariosVista(_VistaConDetalle):
    ACCIONES = [("activar", "Activar"), ("desactivar", "Desactivar"), ("desbloquear", "Desbloquear"),
                ("forzar_cambio", "Forzar cambio de contraseña"), ("reiniciar_mfa", "Reiniciar segundo factor"),
                ("cerrar_sesiones", "Cerrar sus sesiones")]

    def __init__(self, estado):
        super().__init__()
        self.estado = estado
        disposicion = _vista_base(self, "Usuarios",
                                  "Cuentas de la consola. Las cuentas nuevas y sus logins de base de datos los crea "
                                  "el administrador de la BD con la herramienta de administración.")
        divisor = QSplitter()
        divisor.addWidget(self._armar_tabla([
            Columna("Usuario", lambda u: u[1]),
            Columna("Nombre", lambda u: u[2]),
            Columna("Rol", lambda u: tema.ROLES.get(u[3], u[3])),
            Columna("Estado", lambda u: "Activo" if u[4] else "Inactivo", lambda u: tema.ACENTO if u[4] else tema.PELIGRO),
            Columna("Bloqueado hasta", lambda u: _hora(u[5]) if u[5] and u[5] > datetime.now(u[5].tzinfo) else ""),
            Columna("Cambio de clave", lambda u: "Pendiente" if u[6] else ""),
            Columna("Último ingreso", lambda u: _hora(u[7])),
            Columna("Login de BD", lambda u: u[8] or "—", lambda u: tema.TEXTO_SUAVE),
        ], 2))
        caja, v = _caja_detalle("ACCIONES")
        self.botones = {}
        for clave, texto in self.ACCIONES:
            boton = QPushButton(texto)
            boton.clicked.connect(lambda _=False, c=clave: self._accion(c))
            v.addWidget(boton)
            self.botones[clave] = boton
        self.botones["desactivar"].setObjectName("peligro")
        v.addStretch()
        divisor.addWidget(caja)
        divisor.setSizes([900, 300])
        disposicion.addWidget(divisor, 1)

    def _mostrar(self, u) -> None:
        for boton in self.botones.values():
            boton.setEnabled(u is not None)
            _requiere_admin(boton, self.estado)

    def _accion(self, clave):
        try:
            u = self._actual()
            if clave in ("desactivar", "reiniciar_mfa", "cerrar_sesiones") and QMessageBox.question(
                    self, "Confirmar", f"¿{dict(self.ACCIONES)[clave]} para {u[1]}?") != QMessageBox.Yes:
                return
            self.estado.administrar_usuario(u[0], clave)
        except EntradaInvalida as exc:
            QMessageBox.warning(self, "Dato inválido", str(exc))
        except Exception as exc:  # noqa: BLE001
            from comun.errores import manejar_error
            from consola.estado import PermisoDenegado
            if isinstance(exc, PermisoDenegado):
                QMessageBox.warning(self, "Permiso denegado", str(exc))
            else:
                QMessageBox.critical(self, "Error", manejar_error(exc, "administrar usuario"))

    def refrescar(self, *_):
        self._poner_filas(self.estado.usuarios)
