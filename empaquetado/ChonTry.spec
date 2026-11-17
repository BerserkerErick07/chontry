# Empaquetado de ChonTry en un ejecutable de Windows (no requiere Python instalado).
#   .venv\Scripts\python.exe -m PyInstaller empaquetado\ChonTry.spec --noconfirm
# Resultado: dist\ChonTry\ChonTry.exe (carpeta completa; se distribuye comprimida en un .zip).
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs, collect_submodules

raiz = Path(SPECPATH).parent
ocultos = (collect_submodules("scapy") + collect_submodules("keyring.backends") + collect_submodules("netmiko")
           + collect_submodules("psycopg") + collect_submodules("psycopg_binary")
           + ["consola.__main__", "sensor.__main__", "lanzador.__main__", "lanzador.ventana",
              "herramientas.admin", "herramientas.laboratorio", "herramientas.generar_pcaps"])
datos = ([(str(raiz / "db"), "db"), (str(raiz / "docs"), "docs")]
         + collect_data_files("certifi") + collect_data_files("ntc_templates") + collect_data_files("netmiko"))

a = Analysis([str(raiz / "chontry_app.py")], pathex=[str(raiz)], datas=datos,
             binaries=collect_dynamic_libs("psycopg_binary"), hiddenimports=ocultos,
             excludes=["tkinter", "matplotlib", "IPython"], noarchive=False)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="ChonTry", console=False,
          icon=str(raiz / "empaquetado" / "chontry.ico"), version=None)
coll = COLLECT(exe, a.binaries, a.datas, name="ChonTry")
