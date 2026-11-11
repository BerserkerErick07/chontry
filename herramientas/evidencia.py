"""Genera las imágenes de evidencia para los informes: fragmentos de código y
salidas reales de Bandit, las pruebas y la búsqueda de secretos.

    python herramientas/evidencia.py capturas/evidencia
"""
import os
import subprocess  # nosec B404 - solo ejecuta herramientas del propio proyecto, con lista de argumentos
import sys
from pathlib import Path

from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QColor, QFont, QFontMetrics, QGuiApplication, QImage, QPainter

RAIZ = Path(__file__).resolve().parent.parent
PYTHON = str(RAIZ / ".venv" / "Scripts" / "python.exe")

FONDO, BARRA, TEXTO, SUAVE, VERDE, ROJO, AMARILLO = (
    "#0d1117", "#161b22", "#e6edf3", "#7d8590", "#7ee787", "#ff7b72", "#e3b341")

# (archivo, [(desde, hasta), ...], nombre de la imagen)
FRAGMENTOS = [
    ("comun/validacion.py", [(14, 34), (63, 96)], "codigo_validacion"),
    ("db/002_correcciones_clase3.sql", [(19, 52)], "codigo_sql_inyeccion"),
    ("db/002_correcciones_clase3.sql", [(118, 160)], "codigo_sql_autorizacion"),
    ("comun/errores.py", [(13, 60)], "codigo_errores_log"),
    ("comun/db.py", [(14, 49)], "codigo_tls"),
]


def _ejecutar(*args: str) -> list[str]:
    entorno = {**os.environ, "PYTHONIOENCODING": "utf-8"}
    resultado = subprocess.run(args, cwd=RAIZ, capture_output=True, text=True,  # nosec B603
                               encoding="utf-8", env=entorno, check=False)
    return (resultado.stdout + resultado.stderr).rstrip().splitlines()


def _color_terminal(linea: str) -> str:
    if any(p in linea for p in ("FAIL", "ERROR", "SECRETOS ENCONTRADOS", "NO BLOQUEADO", "PERMITIDO\n")):
        return ROJO
    if any(p in linea for p in (" ok", "OK", "bloqueado", "denegado", "ausente", "0 secretos", "22/22", "aceptados")):
        return VERDE
    if "Issue:" in linea or "Severity:" in linea or "Low:" in linea:
        return AMARILLO
    return TEXTO


def renderizar(titulo: str, lineas: list[tuple[str | None, str, str]], salida: Path, ancho_min: int = 900) -> None:
    """lineas: (numero de línea o None, texto, color)."""
    fuente = QFont("Cascadia Mono")
    fuente.setStyleHint(QFont.Monospace)
    fuente.setPixelSize(15)
    metrica = QFontMetrics(fuente)
    alto_linea = metrica.height() + 3
    margen_num = metrica.horizontalAdvance("0000  ") if any(n for n, _, _ in lineas) else 0
    ancho_texto = max((metrica.horizontalAdvance(t.replace("\t", "    ")) for _, t, _ in lineas), default=0)
    ancho = max(ancho_min, 40 + margen_num + ancho_texto)
    alto = 46 + 16 + alto_linea * len(lineas) + 16

    imagen = QImage(ancho, alto, QImage.Format_RGB32)
    imagen.fill(QColor(FONDO))
    p = QPainter(imagen)
    p.setRenderHint(QPainter.TextAntialiasing)
    p.fillRect(0, 0, ancho, 40, QColor(BARRA))
    for i, color in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        p.setBrush(QColor(color))
        p.setPen(Qt.NoPen)
        p.drawEllipse(16 + i * 20, 14, 12, 12)
    titulo_fuente = QFont("Segoe UI")
    titulo_fuente.setPixelSize(14)
    p.setFont(titulo_fuente)
    p.setPen(QColor(SUAVE))
    p.drawText(QRect(90, 0, ancho - 100, 40), Qt.AlignVCenter | Qt.AlignLeft, titulo)
    p.setFont(fuente)
    y = 46 + 16
    for numero, texto, color in lineas:
        if numero:
            p.setPen(QColor(SUAVE))
            p.drawText(20, y + metrica.ascent(), str(numero).rjust(4))
        p.setPen(QColor(color))
        p.drawText(20 + margen_num, y + metrica.ascent(), texto.replace("\t", "    "))
        y += alto_linea
    p.end()
    imagen.save(str(salida))


def fragmento_codigo(archivo: str, rangos, salida: Path) -> None:
    todas = (RAIZ / archivo).read_text(encoding="utf-8").splitlines()
    rangos = [(desde, min(hasta, len(todas))) for desde, hasta in rangos]
    lineas = []
    for i, (desde, hasta) in enumerate(rangos):
        if i:
            lineas.append((None, "    ⋮", SUAVE))
        for n in range(desde, min(hasta, len(todas)) + 1):
            texto = todas[n - 1]
            color = SUAVE if texto.strip().startswith(("#", "--")) else TEXTO
            lineas.append((str(n), texto, color))
    renderizar(f"chontry/{archivo}   (líneas {', '.join(f'{a}-{b}' for a, b in rangos)})", lineas, salida)


def salida_terminal(titulo: str, lineas: list[str], salida: Path) -> None:
    renderizar(titulo, [(None, l, _color_terminal(l)) for l in lineas], salida)


def main() -> int:
    destino = Path(sys.argv[1] if len(sys.argv) > 1 else RAIZ / "capturas" / "evidencia")
    destino.mkdir(parents=True, exist_ok=True)
    app = QGuiApplication(sys.argv)  # noqa: F841 - necesario para las fuentes

    for archivo, rangos, nombre in FRAGMENTOS:
        fragmento_codigo(archivo, rangos, destino / f"{nombre}.png")

    bandit = _ejecutar(str(RAIZ / ".venv" / "Scripts" / "bandit.exe"), "-r", "comun", "consola", "-f", "txt")
    bandit = [l for l in bandit if not l.startswith("[")]   # sin las líneas [main] INFO
    salida_terminal("PS chontry> bandit -r comun consola", bandit, destino / "sast_bandit.png")

    pruebas = _ejecutar(PYTHON, "-m", "unittest", "discover", "-s", "pruebas", "-t", ".", "-v")
    pruebas = [l.split(" (pruebas.")[0] + l.split(")", 1)[1] if " (pruebas." in l else l for l in pruebas]
    salida_terminal("PS chontry> python -m unittest discover -s pruebas -v", pruebas, destino / "pruebas_unitarias.png")

    secretos = _ejecutar(PYTHON, "herramientas/buscar_secretos.py")
    salida_terminal("PS chontry> python herramientas/buscar_secretos.py", secretos, destino / "revision_secretos.png")

    neon = (RAIZ / "db" / "pruebas" / "resultado_2026-11-03.txt").read_text(encoding="utf-8").splitlines()
    salida_terminal("Neon SQL · pruebas de las migraciones 002-004", neon, destino / "pruebas_neon.png")

    for archivo in sorted(destino.glob("*.png")):
        print(f"{archivo.name:32} {archivo.stat().st_size // 1024:>5} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main())
