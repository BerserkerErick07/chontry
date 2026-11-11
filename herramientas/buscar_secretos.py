"""Búsqueda de secretos en el repositorio (NIST SSDF PS.1).

Complemento de gitleaks mientras no esté instalado:  python herramientas/buscar_secretos.py
Devuelve código 1 si encuentra algo, para poder usarlo en un pre-commit.
"""
import re
import subprocess  # nosec B404 - solo ejecuta git ls-files
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
EXCLUIR = {".venv", "__pycache__", "capturas", "logs", ".git"}
EXTENSIONES = {".py", ".sql", ".md", ".txt", ".yaml", ".yml", ".toml", ".json", ".bat", ".ps1", ".cfg", ".ini", ".env", ""}

PATRONES = {
    "Contraseña de Neon": re.compile(r"npg_[A-Za-z0-9]{8,}"),
    "URL de BD con contraseña": re.compile(r"postgres(?:ql)?://[^:/\s]+:(?!CONTRASENA@)[^@\s]+@"),
    "Asignación de secreto": re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\s*=\s*['\"][^'\"]{6,}['\"]"),
    "Clave de AWS": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Token de GitHub": re.compile(r"gh[pousr]_[A-Za-z0-9]{36}"),
    "Llave privada": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}


def archivos():
    """Lo que iría al repositorio: con git, los archivos versionados o no ignorados (como gitleaks);
    sin git, todo menos lo excluido y los .env locales (que .gitignore deja fuera)."""
    if (RAIZ / ".git").exists():
        salida = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],  # nosec B603 B607
                                cwd=RAIZ, capture_output=True, text=True, check=True).stdout
        for nombre in salida.splitlines():
            ruta = RAIZ / nombre
            if ruta.is_file() and (ruta.suffix in EXTENSIONES or ruta.name.startswith(".env")):
                yield ruta
        return
    for ruta in RAIZ.rglob("*"):
        if ruta.is_file() and not EXCLUIR.intersection(ruta.relative_to(RAIZ).parts) \
                and (ruta.suffix in EXTENSIONES or ruta.name == ".env.example") \
                and not (ruta.name.startswith(".env") and ruta.name != ".env.example"):
            yield ruta


# Línea revisada a mano y marcada como dato de prueba (equivale al allowlist de gitleaks)
MARCA_FICTICIO = "# secreto-ficticio"


def main() -> int:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    hallazgos, permitidos, revisados = [], [], 0
    for ruta in archivos():
        revisados += 1
        texto = ruta.read_text(encoding="utf-8", errors="replace")
        for numero, linea in enumerate(texto.splitlines(), 1):
            for nombre, patron in PATRONES.items():
                if patron.search(linea) and ruta.name != Path(__file__).name:
                    destino = permitidos if MARCA_FICTICIO in linea else hallazgos
                    destino.append(f"{ruta.relative_to(RAIZ)}:{numero}  {nombre}")
    print(f"Raíz: {RAIZ.name}/   Archivos revisados: {revisados}   Patrones: {len(PATRONES)}")
    for nombre in PATRONES:
        print(f"  - {nombre}")
    print()
    if permitidos:
        print(f"Datos de prueba marcados '{MARCA_FICTICIO}' (revisados, no son secretos reales): {len(permitidos)}")
        print("\n".join("  " + p for p in permitidos))
        print()
    if hallazgos:
        print(f"SECRETOS ENCONTRADOS: {len(hallazgos)}")
        print("\n".join(hallazgos))
        return 1
    print("Resultado: 0 secretos encontrados.")
    print(".env en .gitignore:", ".env" in (RAIZ / ".gitignore").read_text(encoding="utf-8").split())
    return 0


if __name__ == "__main__":
    sys.exit(main())
