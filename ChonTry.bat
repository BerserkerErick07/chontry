@echo off
rem Abre la consola de ChonTry. La configuracion se lee del archivo .env de esta carpeta.
cd /d "%~dp0"
if not exist ".venv\Scripts\pythonw.exe" (
    echo No se encontro el entorno virtual. Ejecute primero instalar.bat
    pause
    exit /b 1
)
start "" ".venv\Scripts\pythonw.exe" -m consola
