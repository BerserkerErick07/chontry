"""Piezas reutilizables de la interfaz."""
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QFrame, QLabel, QMessageBox, QTableView, QVBoxLayout, QAbstractItemView, QHeaderView

from comun.errores import manejar_error
from comun.validacion import EntradaInvalida
from consola import tema
from consola.estado import PermisoDenegado


def accion_segura(metodo):
    """Ejecuta una acción de la interfaz sin exponer errores internos al usuario (ASVS V7 7.4.1)."""
    @wraps(metodo)
    def envoltura(self, *_):
        try:
            return metodo(self)
        except EntradaInvalida as exc:
            QMessageBox.warning(self, "Dato inválido", str(exc))
        except PermisoDenegado as exc:
            QMessageBox.warning(self, "Permiso denegado", str(exc))
        except Exception as exc:  # noqa: BLE001 - se registra el detalle y se muestra un mensaje genérico
            QMessageBox.critical(self, "Error", manejar_error(exc, metodo.__qualname__))
    return envoltura


@dataclass
class Columna:
    titulo: str
    valor: Callable[[Any], Any]
    color: Callable[[Any], str | None] | None = None
    alineacion: Qt.AlignmentFlag = Qt.AlignLeft | Qt.AlignVCenter


class ModeloTabla(QAbstractTableModel):
    def __init__(self, columnas: list[Columna]):
        super().__init__()
        self._columnas = columnas
        self._filas: list = []

    def set_filas(self, filas) -> None:
        self.beginResetModel()
        self._filas = list(filas)
        self.endResetModel()

    def fila(self, indice: int):
        return self._filas[indice]

    def filas(self) -> list:
        return self._filas

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._filas)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._columnas)

    def headerData(self, seccion, orientacion, rol=Qt.DisplayRole):
        if orientacion == Qt.Horizontal and rol == Qt.DisplayRole:
            return self._columnas[seccion].titulo
        return None

    def data(self, indice, rol=Qt.DisplayRole):
        if not indice.isValid():
            return None
        columna = self._columnas[indice.column()]
        objeto = self._filas[indice.row()]
        if rol == Qt.DisplayRole:
            valor = columna.valor(objeto)
            return "" if valor is None else str(valor)
        if rol == Qt.ForegroundRole and columna.color:
            color = columna.color(objeto)
            return QColor(color) if color else None
        if rol == Qt.TextAlignmentRole:
            return int(columna.alineacion)
        return None


def crear_tabla(modelo: ModeloTabla, estirar: int | None = None) -> QTableView:
    tabla = QTableView()
    tabla.setModel(modelo)
    tabla.setSelectionBehavior(QAbstractItemView.SelectRows)
    tabla.setSelectionMode(QAbstractItemView.SingleSelection)
    tabla.setEditTriggers(QAbstractItemView.NoEditTriggers)
    tabla.setAlternatingRowColors(True)
    tabla.setShowGrid(False)
    tabla.verticalHeader().setVisible(False)
    tabla.verticalHeader().setDefaultSectionSize(30)
    cabecera = tabla.horizontalHeader()
    cabecera.setSectionResizeMode(QHeaderView.ResizeToContents)
    cabecera.setHighlightSections(False)
    if estirar is not None:
        cabecera.setSectionResizeMode(estirar, QHeaderView.Stretch)
    else:
        cabecera.setStretchLastSection(True)
    return tabla


def seleccionar_por_id(tabla: QTableView, modelo: ModeloTabla, objetivo) -> None:
    """Vuelve a seleccionar la fila con ese id después de refrescar el modelo."""
    if objetivo is None:
        return
    for i, fila in enumerate(modelo.filas()):
        if fila.id == objetivo:
            tabla.selectRow(i)
            return


class TarjetaKpi(QFrame):
    def __init__(self, nombre: str, color: str):
        super().__init__()
        self.setObjectName("tarjeta")
        self.setStyleSheet(f"QFrame#tarjeta {{ border-left: 4px solid {color}; }}")
        disposicion = QVBoxLayout(self)
        disposicion.setContentsMargins(16, 12, 16, 12)
        self.valor = QLabel("0")
        self.valor.setObjectName("kpiValor")
        self.valor.setStyleSheet(f"color: {color};")
        etiqueta = QLabel(nombre)
        etiqueta.setObjectName("kpiNombre")
        disposicion.addWidget(self.valor)
        disposicion.addWidget(etiqueta)

    def fijar(self, valor: int) -> None:
        self.valor.setText(str(valor))


def color_severidad(severidad: str) -> str:
    return tema.SEVERIDAD.get(severidad, tema.TEXTO_SUAVE)


def titulo_vista(texto: str, subtitulo: str) -> QFrame:
    caja = QFrame()
    disposicion = QVBoxLayout(caja)
    disposicion.setContentsMargins(0, 0, 0, 4)
    disposicion.setSpacing(2)
    t = QLabel(texto)
    t.setObjectName("titulo")
    s = QLabel(subtitulo)
    s.setObjectName("subtitulo")
    s.setWordWrap(True)
    disposicion.addWidget(t)
    disposicion.addWidget(s)
    return caja
