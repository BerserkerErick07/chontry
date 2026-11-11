@echo off
rem Instalacion de ChonTry en Windows: crea el entorno virtual e instala las dependencias.
rem Requisito: Python 3.12 (https://www.python.org/downloads/ o "winget install Python.Python.3.12").
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
    py -3.12 -m venv .venv
) else (
    python -m venv .venv
)
if not exist ".venv\Scripts\python.exe" (
    echo No se pudo crear el entorno virtual. Instale Python 3.12 y vuelva a intentarlo.
    pause
    exit /b 1
)
".venv\Scripts\python.exe" -m pip install --upgrade pip
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if not exist ".env" copy ".env.example" ".env" >nul
echo.
echo Listo. Edite el archivo .env (ver docs\manual_instalacion.md) y abra ChonTry.bat
pause
