"""Lógica del Centro de control (sin interfaz): PostgreSQL portable, laboratorio y procesos.

Todo lo que se escribe va a la carpeta del usuario (%LOCALAPPDATA%\\ChonTry), nunca a la
carpeta del programa ni al repositorio:
    postgres\\        PostgreSQL 17 portable (se descarga la primera vez, sin administrador)
    .env.pruebas     superusuario del PostgreSQL local (credencial de prueba generada aquí)
    .env.lab         logins, usuarios con TOTP y clave maestra del laboratorio
    datos\\           logs, buffer del sensor y caché
    pcaps\\           capturas de ataques de laboratorio
SOLO para laboratorio y auditoría: la operación real usa la base de datos de producción.
"""
from __future__ import annotations

import ctypes
import os
import secrets
import shutil
import subprocess  # nosec B404 - ejecuta los propios componentes de ChonTry y PostgreSQL
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

import psycopg

from comun.config import CONGELADO, RAIZ, casa_usuario, leer_env

URL_POSTGRES = "https://get.enterprisedb.com/postgresql/postgresql-17.6-1-windows-x64-binaries.zip"
PUERTO = 54330
BD_LAB = "chontry_lab"
SIN_VENTANA = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class Rutas:
    def __init__(self, casa: Path | None = None):
        self.casa = casa or casa_usuario()
        self.postgres = self.casa / "postgres"
        self.bin = self.postgres / "pgsql" / "bin"
        self.datos_pg = self.postgres / "datos"
        self.env_pruebas = self.casa / ".env.pruebas"
        self.env_lab = self.casa / ".env.lab"
        self.datos = self.casa / "datos"
        self.pcaps = self.casa / "pcaps"
        self.docs = self.casa / "docs"
        for carpeta in (self.datos, self.pcaps):
            carpeta.mkdir(parents=True, exist_ok=True)

    @property
    def bandera_sensor(self) -> Path:
        return self.datos / "detener.sensor"


# --------------------------------------------------------------- procesos
def comando(subprograma: str, *argumentos: str) -> list[str]:
    """Línea de comandos de un componente: `ChonTry.exe consola` o `python -m consola`."""
    if CONGELADO:
        return [sys.executable, subprograma, *argumentos]
    modulos = {"consola": "consola", "sensor": "sensor"}
    python = Path(sys.executable)
    # Los componentes sin ventana usan pythonw para no abrir una consola negra
    sin_consola = python.with_name("pythonw.exe")
    ejecutable = str(sin_consola if sin_consola.exists() else python)
    return [ejecutable, "-m", modulos[subprograma], *argumentos]


def lanzar(subprograma: str, *argumentos: str) -> subprocess.Popen:
    return subprocess.Popen(comando(subprograma, *argumentos), cwd=str(RAIZ), creationflags=SIN_VENTANA,  # nosec B603
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def es_windows() -> bool:
    return os.name == "nt"


def npcap_instalado() -> bool:
    return es_windows() and (Path(os.environ.get("WINDIR", r"C:\Windows")) / "System32" / "Npcap").is_dir()


def es_administrador() -> bool:
    if not es_windows():
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except OSError:
        return False


def lanzar_como_administrador(subprograma: str, *argumentos: str) -> bool:
    """Pide elevación (aviso de Windows). Devuelve False si el usuario la rechaza."""
    linea = comando(subprograma, *argumentos)
    parametros = subprocess.list2cmdline(linea[1:])
    resultado = ctypes.windll.shell32.ShellExecuteW(None, "runas", linea[0], parametros, str(RAIZ), 0)
    return resultado > 32


def interfaz_predeterminada() -> tuple[str, str] | None:
    """(nombre para captura, descripción con IP) de la tarjeta con la ruta por defecto. Necesita Npcap en Windows."""
    try:
        from scapy.all import conf
        interfaz = conf.iface
        nombre = getattr(interfaz, "network_name", None) or str(interfaz)
        return nombre, f"{getattr(interfaz, 'description', nombre)} · {getattr(interfaz, 'ip', '')}"
    except Exception:   # noqa: BLE001 - sin Npcap o sin red: no hay captura en vivo
        return None


# --------------------------------------------------------- PostgreSQL portable
class PostgresPortable:
    def __init__(self, rutas: Rutas):
        self.r = rutas

    def instalado(self) -> bool:
        return (self.r.bin / ("postgres.exe" if es_windows() else "postgres")).is_file()

    def descargar(self, progreso=lambda texto: None) -> None:
        self.r.postgres.mkdir(parents=True, exist_ok=True)
        zip_local = os.environ.get("CHONTRY_PG_ZIP")
        destino = Path(zip_local) if zip_local else self.r.postgres / "postgresql.zip"
        if not zip_local:
            progreso("Descargando PostgreSQL 17 portable (unos 330 MB, solo la primera vez)…")
            with urllib.request.urlopen(URL_POSTGRES, timeout=60) as respuesta, open(destino, "wb") as archivo:  # nosec B310 - URL fija https
                total = int(respuesta.headers.get("Content-Length", 0))
                leido, ultimo = 0, -1
                while bloque := respuesta.read(1 << 20):
                    archivo.write(bloque)
                    leido += len(bloque)
                    porcentaje = leido * 100 // total if total else 0
                    if porcentaje // 5 != ultimo:
                        ultimo = porcentaje // 5
                        progreso(f"Descargando PostgreSQL… {porcentaje} %")
        progreso("Descomprimiendo PostgreSQL…")
        omitir = ("pgAdmin", "StackBuilder", "/doc/", "/symbols/", "/include/")
        with zipfile.ZipFile(destino) as z:
            for miembro in z.infolist():
                if not any(o in miembro.filename for o in omitir):
                    z.extract(miembro, self.r.postgres)
        if not zip_local:
            destino.unlink(missing_ok=True)

    def inicializado(self) -> bool:
        return (self.r.datos_pg / "PG_VERSION").is_file() and self.r.env_pruebas.is_file()

    def inicializar(self, progreso=lambda texto: None) -> None:
        progreso("Creando la base de datos local…")
        if self.r.datos_pg.exists():
            shutil.rmtree(self.r.datos_pg)
        clave = secrets.token_urlsafe(24)
        archivo_clave = self.r.postgres / "pw.tmp"
        archivo_clave.write_text(clave, encoding="utf-8")
        try:
            self._ejecutar("initdb", "-D", str(self.r.datos_pg), "-U", "postgres", "-A", "scram-sha-256",
                           f"--pwfile={archivo_clave}", "-E", "UTF8", "--locale=C")
        finally:
            archivo_clave.unlink(missing_ok=True)
        self.r.env_pruebas.write_text(
            "# PostgreSQL LOCAL del Centro de control de ChonTry (credencial de prueba generada en este equipo)\n"
            f"CHONTRY_PRUEBAS_PG_ADMIN=postgresql://postgres:{clave}@localhost:{PUERTO}/postgres\n", encoding="utf-8")

    def url_superusuario(self) -> str:
        return leer_env(self.r.env_pruebas)["CHONTRY_PRUEBAS_PG_ADMIN"]

    def activo(self) -> bool:
        try:
            with psycopg.connect(self.url_superusuario(), connect_timeout=2):
                return True
        except (psycopg.Error, KeyError):
            return False

    def iniciar(self) -> None:
        if self.activo():
            return
        self._ejecutar("pg_ctl", "-D", str(self.r.datos_pg), "-w", "-t", "60",
                       "-o", f"-p {PUERTO} -c listen_addresses=localhost",
                       "-l", str(self.r.postgres / "servidor.log"), "start")

    def detener(self) -> None:
        if self.r.datos_pg.exists():
            self._ejecutar("pg_ctl", "-D", str(self.r.datos_pg), "-m", "fast", "stop", verificar=False)

    def _ejecutar(self, programa: str, *argumentos: str, verificar: bool = True) -> None:
        # Sin tuberías: el servidor que arranca pg_ctl heredaría el pipe y la llamada no terminaría nunca
        ejecutable = self.r.bin / (programa + (".exe" if es_windows() else ""))
        bitacora = self.r.postgres / f"{programa}.salida.log"
        with open(bitacora, "wb") as salida:
            resultado = subprocess.run([str(ejecutable), *argumentos], creationflags=SIN_VENTANA,  # nosec B603
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL if programa == "pg_ctl" else salida, timeout=120)
        if verificar and resultado.returncode != 0:
            detalle = bitacora.read_text(encoding="utf-8", errors="replace")[-300:]
            raise RuntimeError(f"{programa} falló (código {resultado.returncode}). {detalle}")


# ------------------------------------------------------------- laboratorio
class Laboratorio:
    def __init__(self, rutas: Rutas, postgres: PostgresPortable):
        self.r = rutas
        self.pg = postgres

    def listo(self) -> bool:
        if not self.r.env_lab.is_file():
            return False
        try:
            with psycopg.connect(self.pg.url_superusuario(), connect_timeout=3) as c:
                return c.execute("select 1 from pg_database where datname = %s", (BD_LAB,)).fetchone() is not None
        except (psycopg.Error, KeyError):
            return False

    def montar(self, progreso=lambda texto: None) -> None:
        from herramientas import laboratorio
        progreso("Creando el laboratorio: tablas, logins por rol y usuarios con segundo factor…")
        entorno = laboratorio.montar(self.pg.url_superusuario(), salida=lambda *_: None, bd=BD_LAB, prefijo="ct_lab")
        entorno["CHONTRY_DATOS"] = str(self.r.datos)
        laboratorio.escribir_env(entorno, self.r.env_lab)
        self.generar_pcaps(progreso)

    def registrar_red_local(self, ip: str, progreso=lambda texto: None) -> None:
        """Registra la red /24 del equipo para que el sensor pueda proponer contenciones en vivo."""
        import ipaddress
        from herramientas import admin
        try:
            red = ipaddress.ip_network(f"{ip}/24", strict=False)
        except ValueError:
            return
        if red.overlaps(ipaddress.ip_network("10.10.0.0/16")) or not red.is_private:
            return
        with admin.conectar(self.entorno()["CHONTRY_DB_URL_ADMIN"], permitir_dueno=True) as c:
            existe = c.execute("select 1 from chontry.segmentos_red where red = %s", (str(red),)).fetchone()
            if not existe:
                vlan = c.execute("select coalesce(max(vlan_id), 0) + 1 from chontry.segmentos_red "
                                 "where vlan_id < 999").fetchone()[0]
                admin.registrar_segmento(c, "Red local de este equipo", str(red), vlan, "usuarios")
                progreso(f"Red local {red} registrada en el laboratorio (VLAN {vlan}).")

    def generar_pcaps(self, progreso=lambda texto: None) -> Path:
        from herramientas import generar_pcaps
        progreso("Generando capturas de ataques de laboratorio…")
        generar_pcaps.generar(self.r.pcaps)
        return self.r.pcaps / "todos_los_ataques.pcap"

    def entorno(self) -> dict[str, str]:
        return leer_env(self.r.env_lab)

    def usuarios(self) -> list[dict[str, str]]:
        datos = self.entorno()
        return [{"rol": rol, "usuario": datos[f"LAB_{p}_USUARIO"], "clave": datos[f"LAB_{p}_CLAVE"],
                 "totp": datos[f"LAB_{p}_TOTP"]}
                for p, rol in (("ADMIN", "Administrador"), ("ANALISTA", "Analista"), ("AUDITOR", "Auditor"))
                if f"LAB_{p}_USUARIO" in datos]

    def analizar_captura(self, archivo: Path) -> subprocess.CompletedProcess:
        """Pasa una captura .pcap/.pcapng por el sensor (como en producción) y espera a que termine."""
        return subprocess.run(comando("sensor", "--env", str(self.r.env_lab), "--pcap", str(archivo)),  # nosec B603
                              cwd=str(RAIZ), creationflags=SIN_VENTANA, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=600)

    def estado_sensor(self) -> tuple[str, float | None]:
        """(estado, segundos desde el último reporte) leído de la BD del laboratorio."""
        url = self.entorno().get("CHONTRY_DB_URL_ADMIN")
        if not url:
            return "sin laboratorio", None
        try:
            with psycopg.connect(url, connect_timeout=2) as c:
                fila = c.execute("""select estado::text, extract(epoch from now() - ultimo_heartbeat)
                                    from chontry.sensores order by ultimo_heartbeat desc nulls last limit 1""").fetchone()
        except psycopg.Error:
            return "sin conexión", None
        if not fila:
            return "sin sensor", None
        return fila[0], float(fila[1]) if fila[1] is not None else None


def esperar(condicion, segundos: float) -> bool:
    limite = time.monotonic() + segundos
    while time.monotonic() < limite:
        if condicion():
            return True
        time.sleep(0.5)
    return False
