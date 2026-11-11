@echo off
rem Arranca el LABORATORIO local completo: base de datos, ventana de acceso (codigos),
rem consola y sensor en vivo (este ultimo pide permiso de administrador).
rem Requiere haber montado el laboratorio: .venv\Scripts\python.exe -m herramientas.laboratorio
rem La interfaz de captura se toma de CHONTRY_LAB_INTERFAZ en .env.lab
cd /d "%~dp0"
if not exist ".env.lab" (
    echo No hay laboratorio. Ejecute: .venv\Scripts\python.exe -m herramientas.laboratorio
    pause
    exit /b 1
)
set "PGBIN=%LOCALAPPDATA%\chontry-pg\pgsql\bin"
set "PGDATA=%LOCALAPPDATA%\chontry-pg\datos"
if exist "%PGBIN%\pg_ctl.exe" (
    "%PGBIN%\pg_isready.exe" -h localhost -p 54329 >nul 2>nul || start "" /min "%PGBIN%\pg_ctl.exe" -D "%PGDATA%" -o "-p 54329 -c listen_addresses=localhost" -l "%LOCALAPPDATA%\chontry-pg\servidor.log" start
    timeout /t 4 /nobreak >nul
)
start "ChonTry - acceso laboratorio" powershell -NoExit -Command "$env:CHONTRY_ENV='.env.lab'; .\.venv\Scripts\python.exe -m herramientas.acceso_lab"
set "CHONTRY_ENV=.env.lab"
start "" ".venv\Scripts\pythonw.exe" -m consola
rem El sensor necesita permisos de administrador para capturar (aparece el aviso de Windows)
powershell -NoProfile -Command "Start-Process powershell -Verb RunAs -ArgumentList ('-NoExit -ExecutionPolicy Bypass -File \"' + '%~dp0herramientas\sensor_lab.ps1' + '\"')"
