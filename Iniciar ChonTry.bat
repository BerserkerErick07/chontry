@echo off
rem ============================================================================
rem  ChonTry - INICIO CON UN CLIC
rem  La primera vez prepara todo (Python, librerias). Despues abre el Centro de
rem  control, que enciende la base de datos de pruebas, el sensor y la consola.
rem ============================================================================
chcp 65001 >nul
title ChonTry - preparando
cd /d "%~dp0"

if exist ".venv\Scripts\pythonw.exe" goto revisar_librerias

echo.
echo  ChonTry: primera vez en este equipo. Preparando todo (tarda unos minutos)...
echo.
set "PYEXE="
for /f "delims=" %%p in ('py -3.12 -c "import sys; print(sys.executable)" 2^>nul') do set "PYEXE=%%p"
if not defined PYEXE if exist "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" set "PYEXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
if not defined PYEXE (
    echo  No se encontro Python 3.12. Se puede instalar el oficial de python.org con winget.
    choice /c SN /m " Instalar Python 3.12 ahora"
    if errorlevel 2 goto sin_python
    winget install --id Python.Python.3.12 --exact --scope user --silent --accept-package-agreements --accept-source-agreements
    set "PYEXE=%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
)
if not exist "%PYEXE%" goto sin_python
"%PYEXE%" -m venv .venv || goto error

:revisar_librerias
rem Instala o actualiza las librerias cuando cambia requirements.txt (por ejemplo, tras un git pull)
fc /b requirements.txt ".venv\requisitos-instalados.txt" >nul 2>nul
if not errorlevel 1 goto iniciar
echo  Instalando librerias de ChonTry...
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check --upgrade pip >nul
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt || goto error
copy /y requirements.txt ".venv\requisitos-instalados.txt" >nul

:iniciar
start "" ".venv\Scripts\pythonw.exe" -m lanzador
exit /b 0

:sin_python
echo.
echo  Instale Python 3.12 desde https://www.python.org/downloads/ (marque "Add python.exe to PATH")
echo  y vuelva a abrir este archivo.
pause
exit /b 1

:error
echo.
echo  Algo fallo al preparar ChonTry. Revise su conexion a internet y vuelva a intentarlo.
echo  Detalle: docs\manual_instalacion.md (seccion Solucion de problemas).
pause
exit /b 1
