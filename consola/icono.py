"""Icono de ChonTry dibujado con Qt (escudo azul marino con una «C» verde)."""
from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

from consola import tema


def pixmap(tam: int = 256) -> QPixmap:
    imagen = QPixmap(tam, tam)
    imagen.fill(Qt.transparent)
    p = QPainter(imagen)
    p.setRenderHint(QPainter.Antialiasing)
    s = tam / 256
    escudo = QPainterPath()
    escudo.moveTo(QPointF(128 * s, 12 * s))
    escudo.lineTo(QPointF(228 * s, 50 * s))
    escudo.cubicTo(QPointF(228 * s, 150 * s), QPointF(190 * s, 210 * s), QPointF(128 * s, 244 * s))
    escudo.cubicTo(QPointF(66 * s, 210 * s), QPointF(28 * s, 150 * s), QPointF(28 * s, 50 * s))
    escudo.closeSubpath()
    p.fillPath(escudo, QColor(tema.MARINO))
    pluma = QPen(QColor("#3ecf8e"), 26 * s, Qt.SolidLine, Qt.RoundCap)
    p.setPen(pluma)
    p.drawArc(QRectF(78 * s, 68 * s, 100 * s, 110 * s), 45 * 16, 270 * 16)
    p.end()
    return imagen


def icono() -> QIcon:
    resultado = QIcon()
    for tam in (16, 24, 32, 48, 64, 128, 256):
        resultado.addPixmap(pixmap(tam))
    return resultado
