"""Colores y hoja de estilos de la consola: blanco, verde esmeralda y azul marino."""

FONDO = "#f3f6f4"          # gris verdoso muy claro
PANEL = "#ffffff"
PANEL_ALTO = "#f7faf8"     # filas alternas, campos
BORDE = "#dbe4df"
TEXTO = "#1b2a35"
TEXTO_SUAVE = "#5d6d78"
ACENTO = "#12805c"         # verde esmeralda (acción principal)
ACENTO_OSCURO = "#0d6548"
ACENTO_CLARO = "#e3f3ec"
MARINO = "#12304a"         # barra lateral
MARINO_ALTO = "#1c4466"
MARINO_TEXTO = "#c9d8e3"
PELIGRO = "#c62828"
EXITO = "#1e8a4c"
AVISO = "#b7791f"

SEVERIDAD = {
    "critica": "#c62828",
    "alta": "#d9480f",
    "media": "#b7791f",
    "baja": "#1d6fb8",
    "info": "#6b7b86",
}
NOMBRE_SEVERIDAD = {"critica": "Crítica", "alta": "Alta", "media": "Media", "baja": "Baja", "info": "Info"}

ESTADO_ALERTA = {
    "nueva": "Nueva", "en_revision": "En revisión", "contenida": "Contenida",
    "falso_positivo": "Falso positivo", "cerrada": "Cerrada",
}
ESTADO_CONTENCION = {
    "propuesta": "Pendiente de aprobación", "aprobada": "Aprobada (enviando)", "aplicada": "En cuarentena",
    "por_revertir": "Liberación pendiente", "fallida": "Fallida", "rechazada": "Rechazada",
    "revertida": "Liberada", "expirada": "Liberada (TTL)",
}
COLOR_CONTENCION = {
    "propuesta": AVISO, "aprobada": AVISO, "aplicada": PELIGRO, "por_revertir": AVISO,
    "rechazada": TEXTO_SUAVE, "revertida": TEXTO_SUAVE, "expirada": TEXTO_SUAVE, "fallida": PELIGRO,
}
ROLES = {"admin": "Administrador", "analista": "Analista", "auditor": "Auditor"}

QSS = f"""
QWidget {{
    background: {FONDO};
    color: {TEXTO};
    font-family: "Segoe UI", "Noto Sans", sans-serif;
    font-size: 10pt;
}}
QDialog, QMessageBox {{ background: {PANEL}; }}
QFrame#panel, QFrame#tarjeta, QFrame#detalle, QFrame#tarjetaAcceso {{
    background: {PANEL};
    border: 1px solid {BORDE};
    border-radius: 10px;
}}
QFrame#encabezado {{ background: {PANEL}; border-bottom: 1px solid {BORDE}; }}
QFrame#bandaAcceso {{ background: {MARINO}; border-top-left-radius: 10px; border-top-right-radius: 10px; }}
QLabel {{ background: transparent; }}
QLabel#marca {{ font-size: 16pt; font-weight: 700; color: {MARINO}; }}
QLabel#marcaClara {{ font-size: 20pt; font-weight: 700; color: #ffffff; }}
QLabel#marcaPunto {{ font-size: 16pt; font-weight: 700; color: {ACENTO}; }}
QLabel#submarca {{ color: {TEXTO_SUAVE}; }}
QLabel#submarcaClara {{ color: {MARINO_TEXTO}; }}
QLabel#titulo {{ font-size: 15pt; font-weight: 600; color: {MARINO}; }}
QLabel#subtitulo {{ color: {TEXTO_SUAVE}; }}
QLabel#seccion {{ color: {ACENTO_OSCURO}; font-size: 8.5pt; font-weight: 700; letter-spacing: 1px; }}
QLabel#kpiValor {{ font-size: 24pt; font-weight: 700; }}
QLabel#kpiNombre {{ color: {TEXTO_SUAVE}; }}
QLabel#insignia {{
    background: {PANEL_ALTO};
    border: 1px solid {BORDE};
    border-radius: 11px;
    padding: 4px 11px;
}}
QLabel#error {{ color: {PELIGRO}; }}
QListWidget#navegacion {{
    background: {MARINO};
    border: none;
    padding-top: 10px;
    outline: 0;
    color: {MARINO_TEXTO};
}}
QListWidget#navegacion::item {{
    padding: 11px 16px;
    margin: 2px 10px;
    border-radius: 7px;
    color: {MARINO_TEXTO};
}}
QListWidget#navegacion::item:selected {{
    background: {MARINO_ALTO};
    color: #ffffff;
    border-left: 4px solid #3ecf8e;
}}
QListWidget#navegacion::item:hover {{ background: {MARINO_ALTO}; color: #ffffff; }}
QFrame#pieNavegacion {{ background: {MARINO}; }}
QLabel#pieNavegacion {{ color: {MARINO_TEXTO}; font-size: 8.5pt; }}
QTableView {{
    background: {PANEL};
    alternate-background-color: {PANEL_ALTO};
    border: 1px solid {BORDE};
    border-radius: 10px;
    gridline-color: {BORDE};
    selection-background-color: {ACENTO_CLARO};
    selection-color: {TEXTO};
}}
QHeaderView::section {{
    background: {PANEL};
    color: {TEXTO_SUAVE};
    border: none;
    border-bottom: 2px solid {BORDE};
    padding: 7px 8px;
    font-weight: 600;
}}
QTableCornerButton::section {{ background: {PANEL}; border: none; }}
QPushButton {{
    background: {PANEL};
    border: 1px solid #c5d2cb;
    border-radius: 7px;
    padding: 7px 15px;
    color: {TEXTO};
}}
QPushButton:hover {{ border-color: {ACENTO}; color: {ACENTO_OSCURO}; }}
QPushButton:disabled {{ color: #a9b5bd; border-color: #e3e9e6; background: {PANEL_ALTO}; }}
QPushButton#primario {{ background: {ACENTO}; color: #ffffff; border: none; font-weight: 600; }}
QPushButton#primario:hover {{ background: {ACENTO_OSCURO}; color: #ffffff; }}
QPushButton#primario:disabled {{ background: #a8d2c2; color: #f4fbf8; }}
QPushButton#peligro {{ background: #fff5f5; border-color: #f0b8b8; color: {PELIGRO}; }}
QPushButton#peligro:hover {{ background: #fdeaea; border-color: {PELIGRO}; }}
QPushButton#peligro:disabled {{ background: {PANEL_ALTO}; border-color: #e3e9e6; color: #c3cbd0; }}
QPushButton#enlace {{ background: transparent; border: none; color: {ACENTO_OSCURO}; text-decoration: underline; }}
QComboBox, QLineEdit, QSpinBox, QDateEdit, QPlainTextEdit {{
    background: {PANEL};
    border: 1px solid #c5d2cb;
    border-radius: 7px;
    padding: 5px 9px;
    selection-background-color: {ACENTO_CLARO};
    selection-color: {TEXTO};
}}
QSpinBox, QDateEdit {{ min-height: 24px; }}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDateEdit:focus, QPlainTextEdit:focus {{ border: 2px solid {ACENTO}; }}
QLineEdit[invalido="true"] {{ border: 2px solid {PELIGRO}; }}
QComboBox QAbstractItemView {{ background: {PANEL}; selection-background-color: {ACENTO_CLARO}; }}
QPlainTextEdit#comandos {{ font-family: "Cascadia Mono", "Consolas", monospace; background: #f5f9f7; color: {ACENTO_OSCURO}; }}
QCheckBox, QRadioButton {{ background: transparent; spacing: 8px; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 16px; height: 16px; border: 1px solid #9fb3a9; background: {PANEL};
}}
QCheckBox::indicator {{ border-radius: 4px; }}
QRadioButton::indicator {{ border-radius: 9px; }}
QCheckBox::indicator:checked, QRadioButton::indicator:checked {{ background: {ACENTO}; border: 3px solid {ACENTO_CLARO}; }}
QCheckBox::indicator:disabled, QRadioButton::indicator:disabled {{ background: {PANEL_ALTO}; border-color: #dbe4df; }}
QStatusBar {{ background: {PANEL}; color: {TEXTO_SUAVE}; border-top: 1px solid {BORDE}; }}
QSplitter::handle {{ background: {FONDO}; }}
QToolTip {{ background: {MARINO}; color: #ffffff; border: none; padding: 4px; }}
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: #c5d2cb; border-radius: 4px; min-height: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
"""
