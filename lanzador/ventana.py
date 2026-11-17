"""Centro de control de ChonTry: enciende todo con un clic y muestra el acceso de prueba."""
from __future__ import annotations

import shutil
import time
from pathlib import Path

import pyotp
from PySide6.QtCore import QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QTextDocument
from PySide6.QtWidgets import (QFileDialog, QFrame, QGridLayout, QHBoxLayout, QLabel, QLineEdit, QMainWindow,
                               QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea, QVBoxLayout,
                               QWidget)

from comun.config import RAIZ
from comun.errores import manejar_error
from consola import tema
from consola.icono import icono
from lanzador import servicios as s
from sensor import VERSION

DOCUMENTOS = [("Manual de uso", "manual_usuario"), ("Manual de instalación", "manual_instalacion"),
              ("Manual de funcionamiento", "manual_funcionamiento"), ("Guía de pruebas", "guia_de_pruebas"),
              ("Guía de uso real", "guia_uso_real")]


class Tarea(QThread):
    """Ejecuta una función larga sin congelar la ventana."""
    mensaje = Signal(str)
    terminada = Signal(bool, str)

    def __init__(self, funcion):
        super().__init__()
        self._funcion = funcion

    def run(self):
        try:
            self._funcion(self.mensaje.emit)
            self.terminada.emit(True, "")
        except Exception as exc:  # noqa: BLE001 - se informa en la bitácora de la ventana
            self.terminada.emit(False, f"{manejar_error(exc, 'centro de control')} ({type(exc).__name__}: {exc})"[:400])


class Vigia(QThread):
    """Revisa cada pocos segundos el estado de la base de datos y del sensor."""
    estado = Signal(dict)

    def __init__(self, pg: s.PostgresPortable, lab: s.Laboratorio):
        super().__init__()
        self.pg, self.lab = pg, lab
        self.activo = True

    def run(self):
        while self.activo:
            datos = {"bd": self.pg.instalado() and self.pg.inicializado() and self.pg.activo()}
            datos["lab"] = datos["bd"] and self.lab.listo()
            datos["sensor"] = self.lab.estado_sensor() if datos["lab"] else ("sin laboratorio", None)
            self.estado.emit(datos)
            for _ in range(30):
                if not self.activo:
                    return
                self.msleep(100)


def _tarjeta(titulo: str) -> tuple[QFrame, QVBoxLayout]:
    caja = QFrame()
    caja.setObjectName("panel")
    v = QVBoxLayout(caja)
    v.setContentsMargins(18, 14, 18, 16)
    v.setSpacing(8)
    etiqueta = QLabel(titulo)
    etiqueta.setObjectName("seccion")
    v.addWidget(etiqueta)
    return caja, v


class FilaComponente:
    def __init__(self, rejilla: QGridLayout, fila: int, nombre: str, detalle: str, texto_boton: str, accion):
        self.punto = QLabel("●")
        self.nombre = QLabel(f"<b>{nombre}</b><br><span style='color:{tema.TEXTO_SUAVE}'>{detalle}</span>")
        self.estado = QLabel("—")
        self.boton = QPushButton(texto_boton)
        self.boton.clicked.connect(accion)
        for col, w in enumerate((self.punto, self.nombre, self.estado, self.boton)):
            rejilla.addWidget(w, fila, col)
        self.fijar("gris", "—")

    def fijar(self, color: str, texto: str):
        colores = {"verde": tema.EXITO, "rojo": tema.PELIGRO, "ambar": tema.AVISO, "gris": "#a9b5bd"}
        self.punto.setStyleSheet(f"color:{colores[color]}; font-size:16pt;")
        self.estado.setText(texto)


class FilaAcceso(QFrame):
    """Usuario de prueba: usuario, contraseña y código de 6 dígitos con botones de copiar."""

    def __init__(self, usuario: dict, copiar):
        super().__init__()
        self.secreto = usuario["totp"]
        self.setStyleSheet(f"QFrame {{ background:{tema.PANEL_ALTO}; border:1px solid {tema.BORDE}; border-radius:8px; }}"
                           "QLabel { border:none; background:transparent; }")
        rejilla = QGridLayout(self)
        rejilla.setContentsMargins(12, 8, 12, 8)
        rejilla.setHorizontalSpacing(8)
        rol = QLabel(f"<b style='color:{tema.MARINO}'>{usuario['rol']}</b>")
        rejilla.addWidget(rol, 0, 0, 1, 4)
        self.campos = []
        for fila, (titulo, valor, oculto) in enumerate((("Usuario", usuario["usuario"], False),
                                                        ("Contraseña", usuario["clave"], True)), start=1):
            rejilla.addWidget(QLabel(titulo), fila, 0)
            campo = QLineEdit(valor)
            campo.setReadOnly(True)
            if oculto:
                campo.setEchoMode(QLineEdit.Password)
                ver = QPushButton("Ver")
                ver.setCheckable(True)
                ver.toggled.connect(lambda m, c=campo: c.setEchoMode(QLineEdit.Normal if m else QLineEdit.Password))
                rejilla.addWidget(ver, fila, 2)
            rejilla.addWidget(campo, fila, 1)
            boton = QPushButton("Copiar")
            boton.clicked.connect(lambda _=False, v=valor, t=titulo: copiar(v, f"{t} de {usuario['rol']}"))
            rejilla.addWidget(boton, fila, 3)
        rejilla.addWidget(QLabel("Código"), 3, 0)
        self.codigo = QLabel("------")
        self.codigo.setStyleSheet(f"font-family:'Cascadia Mono','Consolas',monospace; font-size:18pt; "
                                  f"font-weight:700; color:{tema.ACENTO_OSCURO}; letter-spacing:4px;")
        rejilla.addWidget(self.codigo, 3, 1)
        self.barra = QProgressBar()
        self.barra.setRange(0, 30)
        self.barra.setTextVisible(False)
        self.barra.setFixedHeight(6)
        self.barra.setStyleSheet(f"QProgressBar {{ background:{tema.BORDE}; border:none; border-radius:3px; }}"
                                 f"QProgressBar::chunk {{ background:{tema.ACENTO}; border-radius:3px; }}")
        rejilla.addWidget(self.barra, 4, 1)
        copiar_codigo = QPushButton("Copiar")
        copiar_codigo.clicked.connect(lambda: copiar(self.codigo.text(), f"Código de {usuario['rol']}"))
        rejilla.addWidget(copiar_codigo, 3, 3)
        rejilla.setColumnStretch(1, 1)
        self.actualizar()

    def actualizar(self):
        self.codigo.setText(pyotp.TOTP(self.secreto).now())
        self.barra.setValue(30 - int(time.time()) % 30)


class CentroDeControl(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ChonTry · Centro de control")
        self.setWindowIcon(icono())
        pantalla = self.screen().availableGeometry() if self.screen() else None
        ancho = min(1180, pantalla.width() - 40) if pantalla else 1180
        alto = min(860, pantalla.height() - 60) if pantalla else 820
        self.resize(ancho, alto)
        self.rutas = s.Rutas()
        self.pg = s.PostgresPortable(self.rutas)
        self.lab = s.Laboratorio(self.rutas, self.pg)
        self.sensor_local = None
        self.consolas: list = []
        self.tarea: Tarea | None = None
        self.filas_acceso: list[FilaAcceso] = []
        self.interfaz = None
        self._construir()
        self.vigia = Vigia(self.pg, self.lab)
        self.vigia.estado.connect(self._al_estado)
        self.vigia.start()
        reloj = QTimer(self)
        reloj.timeout.connect(self._tic)
        reloj.start(1000)
        QTimer.singleShot(400, self.iniciar_todo)

    # ------------------------------------------------------------ interfaz
    def _construir(self):
        central = QWidget()
        raiz = QVBoxLayout(central)
        raiz.setContentsMargins(0, 0, 0, 0)
        raiz.setSpacing(0)
        banda = QFrame()
        banda.setObjectName("banda")
        banda.setStyleSheet(f"QFrame#banda {{ background:{tema.MARINO}; }}")
        b = QHBoxLayout(banda)
        b.setContentsMargins(26, 16, 26, 16)
        marca = QLabel("Chon<span style='color:#3ecf8e'>Try</span>")
        marca.setStyleSheet("color:#ffffff; font-size:20pt; font-weight:700; background:transparent;")
        sub = QLabel(f"Centro de control · laboratorio de pruebas y auditoría · v{VERSION}")
        sub.setStyleSheet(f"color:{tema.MARINO_TEXTO}; background:transparent;")
        b.addWidget(marca)
        b.addSpacing(12)
        b.addWidget(sub)
        b.addStretch()
        self.boton_todo = QPushButton("Iniciar todo")
        self.boton_todo.setObjectName("primario")
        self.boton_todo.clicked.connect(self.iniciar_todo)
        detener = QPushButton("Detener todo")
        detener.setObjectName("peligro")
        detener.clicked.connect(self.detener_todo)
        b.addWidget(self.boton_todo)
        b.addWidget(detener)
        raiz.addWidget(banda)

        cuerpo = QGridLayout()
        cuerpo.setContentsMargins(22, 18, 22, 18)
        cuerpo.setSpacing(14)

        caja, v = _tarjeta("COMPONENTES")
        rejilla = QGridLayout()
        rejilla.setHorizontalSpacing(12)
        rejilla.setVerticalSpacing(10)
        self.fila_bd = FilaComponente(rejilla, 0, "Base de datos", "PostgreSQL 17 local (portable)", "Reiniciar",
                                      self.reiniciar_bd)
        self.fila_lab = FilaComponente(rejilla, 1, "Laboratorio", "Tablas, roles, usuarios con 2FA", "Recrear",
                                       self.recrear_laboratorio)
        self.fila_sensor = FilaComponente(rejilla, 2, "Sensor", "Detección y contención", "Captura en vivo",
                                          self.captura_en_vivo)
        self.fila_consola = FilaComponente(rejilla, 3, "Consola", "Interfaz de los analistas", "Abrir consola",
                                           self.abrir_consola)
        rejilla.setColumnStretch(1, 1)
        v.addLayout(rejilla)
        self.aviso_captura = QLabel("")
        self.aviso_captura.setObjectName("subtitulo")
        self.aviso_captura.setWordWrap(True)
        v.addWidget(self.aviso_captura)
        v.addStretch()
        cuerpo.addWidget(caja, 0, 0)

        caja, self.v_acceso = _tarjeta("ACCESO DE PRUEBA — copie y pegue en la consola")
        nota = QLabel("Credenciales generadas solo para este laboratorio. El código cambia cada 30 s y sirve una vez.")
        nota.setObjectName("subtitulo")
        nota.setWordWrap(True)
        self.v_acceso.addWidget(nota)
        self.sin_acceso = QLabel("Se mostrarán cuando el laboratorio esté listo…")
        self.sin_acceso.setObjectName("subtitulo")
        self.v_acceso.addWidget(self.sin_acceso)
        self.v_acceso.addStretch()
        cuerpo.addWidget(caja, 0, 1, 2, 1)

        caja, v = _tarjeta("PROBAR EL SISTEMA")
        fila = QHBoxLayout()
        for texto, accion in (("Simular ataques", self.simular_ataques),
                              ("Analizar una captura (.pcap)…", self.analizar_captura)):
            boton = QPushButton(texto)
            boton.clicked.connect(accion)
            fila.addWidget(boton)
        v.addLayout(fila)
        explicacion = QLabel("«Simular ataques» pasa por el sensor una captura con escaneos, movimiento lateral, "
                             "fuerza bruta y suplantación. Luego revíselos en la consola (Alertas y Cuarentena).")
        explicacion.setObjectName("subtitulo")
        explicacion.setWordWrap(True)
        v.addWidget(explicacion)
        v.addWidget(QLabel("<b>Documentación</b>"))
        rejilla_docs = QGridLayout()
        for i, (texto, nombre) in enumerate(DOCUMENTOS):
            boton = QPushButton(texto)
            boton.clicked.connect(lambda _=False, n=nombre: self.abrir_documento(n))
            rejilla_docs.addWidget(boton, i // 3, i % 3)
        v.addLayout(rejilla_docs)
        cuerpo.addWidget(caja, 1, 0)

        caja, v = _tarjeta("ACTIVIDAD")
        self.bitacora = QPlainTextEdit()
        self.bitacora.setReadOnly(True)
        self.bitacora.setMaximumBlockCount(500)
        self.bitacora.setMinimumHeight(120)
        self.bitacora.setStyleSheet("font-family:'Cascadia Mono','Consolas',monospace; font-size:9pt;")
        v.addWidget(self.bitacora)
        cuerpo.addWidget(caja, 2, 0, 1, 2)
        cuerpo.setColumnStretch(0, 5)
        cuerpo.setColumnStretch(1, 4)
        cuerpo.setRowStretch(2, 1)
        # Con scroll: en pantallas pequeñas (o con zoom de Windows) nada queda fuera de la vista
        contenido = QWidget()
        contenido.setObjectName("contenido")
        contenido.setLayout(cuerpo)
        desplazable = QScrollArea()
        desplazable.setWidgetResizable(True)
        desplazable.setFrameShape(QFrame.NoFrame)
        desplazable.setStyleSheet(f"QScrollArea, QWidget#contenido {{ background:{tema.FONDO}; }}")
        desplazable.setWidget(contenido)
        raiz.addWidget(desplazable, 1)
        self.setCentralWidget(central)
        self.statusBar().showMessage(f"Datos del laboratorio en {self.rutas.casa}")

    def log(self, texto: str):
        self.bitacora.appendPlainText(f"{time.strftime('%H:%M:%S')}  {texto}")

    def _copiar(self, valor: str, que: str):
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(valor)
        self.statusBar().showMessage(f"{que} copiado al portapapeles", 3000)

    def _cargar_acceso(self):
        for fila in self.filas_acceso:
            fila.deleteLater()
        self.filas_acceso = []
        usuarios = self.lab.usuarios()
        self.sin_acceso.setVisible(not usuarios)
        for i, usuario in enumerate(usuarios):
            fila = FilaAcceso(usuario, self._copiar)
            self.v_acceso.insertWidget(2 + i, fila)
            self.filas_acceso.append(fila)

    # --------------------------------------------------------------- estado
    def _tic(self):
        for fila in self.filas_acceso:
            fila.actualizar()
        self.consolas = [p for p in self.consolas if p.poll() is None]
        n = len(self.consolas)
        self.fila_consola.fijar("verde" if n else "gris", f"{n} abierta(s)" if n else "cerrada")

    def _al_estado(self, d: dict):
        self.fila_bd.fijar("verde" if d["bd"] else ("ambar" if self.pg.instalado() else "gris"),
                           "en marcha" if d["bd"] else ("detenida" if self.pg.instalado() else "no instalada"))
        self.fila_lab.fijar("verde" if d["lab"] else "gris", "listo" if d["lab"] else "sin crear")
        if d["lab"] and not self.filas_acceso:
            self._cargar_acceso()
        estado, segundos = d["sensor"]
        vivo = estado == "activo" and segundos is not None and segundos < 90
        local = self.sensor_local is not None and self.sensor_local.poll() is None
        texto = (f"activo · hace {int(segundos)} s" if vivo else estado) + (" · contención" if local and vivo else "")
        self.fila_sensor.fijar("verde" if vivo else ("ambar" if local else "gris"), texto)

    # -------------------------------------------------------------- acciones
    def _ejecutar(self, funcion, al_terminar=None, ocupado="Trabajando…"):
        if self.tarea is not None and self.tarea.isRunning():
            QMessageBox.information(self, "ChonTry", "Espere a que termine la tarea en curso.")
            return
        self.boton_todo.setEnabled(False)
        self.boton_todo.setText(ocupado)
        self.tarea = Tarea(funcion)
        self.tarea.mensaje.connect(self.log)

        def fin(ok, error):
            self.boton_todo.setEnabled(True)
            self.boton_todo.setText("Iniciar todo")
            if not ok:
                self.log(f"ERROR: {error}")
                QMessageBox.warning(self, "ChonTry", f"No se pudo completar:\n{error}")
            elif al_terminar:
                al_terminar()
        self.tarea.terminada.connect(fin)
        self.tarea.start()

    def iniciar_todo(self):
        def trabajo(progreso):
            if not self.pg.instalado():
                self.pg.descargar(progreso)
            if not self.pg.inicializado():
                self.pg.inicializar(progreso)
            progreso("Encendiendo la base de datos…")
            self.pg.iniciar()
            if not self.lab.listo():
                self.lab.montar(progreso)
                progreso("Cargando ataques de ejemplo para que la consola tenga datos…")
                self.lab.analizar_captura(self.rutas.pcaps / "todos_los_ataques.pcap")
            self.interfaz = s.interfaz_predeterminada() if s.npcap_instalado() else None
            if self.interfaz and " · " in self.interfaz[1]:
                self.lab.registrar_red_local(self.interfaz[1].rsplit(" · ", 1)[1], progreso)
            progreso("Base de datos y laboratorio listos.")

        def despues():
            self._cargar_acceso()
            self._iniciar_sensor()
            if not self.consolas:
                self.abrir_consola()
            self.log("Todo en marcha. Copie el usuario, la contraseña y el código del Administrador en la consola.")
        self._ejecutar(trabajo, despues, "Iniciando…")

    def _iniciar_sensor(self):
        if self.interfaz and s.es_windows():
            self.aviso_captura.setText(f"Captura en vivo en: {self.interfaz[1]}")
            if self._lanzar_en_vivo():
                return
        else:
            self.aviso_captura.setText("Captura en vivo no disponible: instale Nmap (incluye Npcap) desde "
                                       "nmap.org y pulse «Captura en vivo». Mientras tanto use «Simular ataques».")
        self._sensor_contencion()

    def _sensor_contencion(self):
        if self.sensor_local is None or self.sensor_local.poll() is not None:
            self.sensor_local = s.lanzar("sensor", "--env", str(self.rutas.env_lab), "--solo-contencion")
            self.log("Sensor en marcha (ejecuta las contenciones que se aprueben en la consola).")

    def _lanzar_en_vivo(self) -> bool:
        self._detener_sensor()
        self.log("Pidiendo permiso de administrador para capturar en vivo (acepte el aviso de Windows)…")
        ok = s.lanzar_como_administrador("sensor", "--env", str(self.rutas.env_lab), "--interfaz", self.interfaz[0],
                                         "--filtro", "not port 443")
        self.log("Sensor capturando en vivo." if ok else "Permiso rechazado: el sensor queda sin captura en vivo.")
        return ok

    def captura_en_vivo(self):
        if not s.npcap_instalado():
            QMessageBox.information(self, "Captura en vivo",
                                    "Para capturar el tráfico de la red en Windows hace falta Npcap.\n\n"
                                    "Instale Nmap desde https://nmap.org/download.html (incluye Npcap) "
                                    "y vuelva a pulsar este botón.")
            return
        self.interfaz = self.interfaz or s.interfaz_predeterminada()
        if not self.interfaz:
            QMessageBox.warning(self, "Captura en vivo", "No se encontró una tarjeta de red con conexión.")
            return
        self.aviso_captura.setText(f"Captura en vivo en: {self.interfaz[1]}")
        if not self._lanzar_en_vivo():
            self._sensor_contencion()

    def _detener_sensor(self):
        self.rutas.bandera_sensor.touch()      # detiene también el sensor que corre como administrador
        if self.sensor_local is not None and self.sensor_local.poll() is None:
            self.sensor_local.terminate()
        self.sensor_local = None

    def abrir_consola(self):
        if not self.rutas.env_lab.is_file():
            QMessageBox.information(self, "ChonTry", "Primero pulse «Iniciar todo».")
            return
        self.consolas.append(s.lanzar("consola", "--env", str(self.rutas.env_lab)))
        self.log("Consola abierta: entre con «Base de datos (operación real)» y los datos de la derecha.")

    def simular_ataques(self):
        def trabajo(progreso):
            archivo = self.lab.generar_pcaps(progreso)
            progreso("El sensor está analizando la captura de ataques…")
            self.lab.analizar_captura(archivo)
            progreso("Listo: revise Alertas y Cuarentena en la consola.")
        self._ejecutar(trabajo, ocupado="Simulando…")

    def analizar_captura(self):
        archivo, _ = QFileDialog.getOpenFileName(self, "Captura a analizar", str(Path.home()),
                                                 "Capturas de red (*.pcap *.pcapng *.cap)")
        if not archivo:
            return

        def trabajo(progreso):
            progreso(f"Analizando {Path(archivo).name}…")
            resultado = self.lab.analizar_captura(Path(archivo))
            progreso("Listo: revise Alertas en la consola." if resultado.returncode == 0
                     else f"El sensor terminó con código {resultado.returncode} (vea datos/sensor.log).")
        self._ejecutar(trabajo, ocupado="Analizando…")

    def reiniciar_bd(self):
        def trabajo(progreso):
            progreso("Reiniciando la base de datos…")
            self.pg.detener()
            self.pg.iniciar()
            progreso("Base de datos en marcha.")
        self._ejecutar(trabajo, ocupado="Reiniciando…")

    def recrear_laboratorio(self):
        if QMessageBox.question(self, "Recrear laboratorio",
                                "Se borrarán las alertas y se generarán usuarios y contraseñas nuevos. ¿Continuar?") \
                != QMessageBox.Yes:
            return
        self._detener_sensor()

        def trabajo(progreso):
            self.pg.iniciar()
            self.lab.montar(progreso)
            self.lab.analizar_captura(self.rutas.pcaps / "todos_los_ataques.pcap")
            progreso("Laboratorio recreado. Cierre las consolas abiertas y vuelva a entrar.")

        def despues():
            self._cargar_acceso()
            self._iniciar_sensor()
        self._ejecutar(trabajo, despues, "Recreando…")

    def abrir_documento(self, nombre: str):
        """Convierte el manual Markdown a HTML (con sus imágenes) y lo abre en el navegador."""
        origen = RAIZ / "docs"
        self.rutas.docs.mkdir(parents=True, exist_ok=True)
        if (origen / "img").is_dir():
            shutil.copytree(origen / "img", self.rutas.docs / "img", dirs_exist_ok=True)
        documento = QTextDocument()
        documento.setMarkdown((origen / f"{nombre}.md").read_text(encoding="utf-8"))
        estilo = ("<style>body{font-family:Segoe UI,Arial,sans-serif;max-width:980px;margin:30px auto;padding:0 24px;"
                  "color:#1b2a35;line-height:1.5}h1,h2,h3{color:#12304a}a{color:#0d6548}"
                  "table{border-collapse:collapse}td,th{border:1px solid #dbe4df;padding:6px 8px}"
                  "pre,code{background:#f5f9f7}img{max-width:100%}</style>")
        html = documento.toHtml().replace("</head>", estilo + "</head>", 1)
        destino = self.rutas.docs / f"{nombre}.html"
        destino.write_text(html, encoding="utf-8")
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(destino)))

    def detener_todo(self):
        self._detener_sensor()
        for consola in self.consolas:
            consola.terminate()
        self.consolas = []
        self.pg.detener()
        self.log("Todo detenido.")

    def closeEvent(self, evento):
        respuesta = QMessageBox.question(self, "Salir", "¿Detener la base de datos, el sensor y las consolas al salir?",
                                         QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel)
        if respuesta == QMessageBox.Cancel:
            evento.ignore()
            return
        self.vigia.activo = False
        self.vigia.wait(3000)
        if respuesta == QMessageBox.Yes:
            self.detener_todo()
        evento.accept()
