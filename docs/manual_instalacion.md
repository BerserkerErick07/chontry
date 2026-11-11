# Manual de instalación — ChonTry

Este manual explica cómo dejar ChonTry funcionando desde cero: la base de datos, la consola de escritorio y el sensor. Si solo quiere **probar** el sistema en su equipo sin red real, vaya directo a la [sección 7 (laboratorio en 10 minutos)](#7-laboratorio-local-en-10-minutos).

> **Convención:** los comandos se escriben en PowerShell desde la carpeta del proyecto (`chontry`). En Linux, cambie `.venv\Scripts\python.exe` por `.venv/bin/python`.

---

## 1. Qué se instala y dónde

| Pieza | Dónde corre | Para qué |
|---|---|---|
| **Base de datos** PostgreSQL 15+ (Neon u otro) | Nube o servidor | Guarda alertas, contenciones, auditoría, usuarios. Aplica permisos por rol |
| **Consola** (`python -m consola`) | El PC de cada administrador o analista (Windows, Linux o macOS) | Ver alertas, aprobar contenciones, reportes |
| **Sensor** (`python -m sensor`) | Un equipo conectado al **puerto SPAN** del switch (Linux recomendado) | Captura el tráfico, detecta ataques y ejecuta la contención en el switch |
| **Herramienta de administración** (`python -m herramientas.admin`) | El equipo del administrador de la BD | Migraciones, logins, usuarios, sensores y switches |

## 2. Requisitos

- **Python 3.12** — Windows: `winget install Python.Python.3.12` · Linux: `sudo apt install python3.12 python3.12-venv`
- **Git** para descargar el código — `winget install Git.Git`
- **PostgreSQL 15 o superior**: una base en [Neon](https://neon.tech) (gratis) o un servidor propio.
- **Solo para el sensor en vivo:**
  - Linux: nada adicional (Scapy usa sockets nativos).
  - Windows: [Npcap](https://npcap.com) instalado (con la opción «Restrict Npcap driver's access to Administrators» si se quiere limitar quién captura).
- **Solo para contención real:** un switch gestionable por SSH (Cisco IOS/NX-OS o HP ProCurve tienen plantilla) con un puerto SPAN configurado hacia el sensor.

## 3. Descargar e instalar

```powershell
git clone https://github.com/BerserkerErick07/chontry.git
cd chontry
.\instalar.bat
```

`instalar.bat` crea el entorno virtual `.venv`, instala las dependencias **con versiones fijas** (`requirements.txt`) y copia `.env.example` como `.env`. En Linux:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp .env.example .env
```

Para comprobar la instalación:

```powershell
.venv\Scripts\python.exe -m unittest discover -s pruebas -t .
```

Deben pasar todas las pruebas (la de integración se salta si no hay un PostgreSQL de pruebas; ver sección 7).

## 4. Preparar la base de datos (lo hace el administrador de la BD, una sola vez)

La herramienta de administración se conecta con el **rol dueño** de la base (en Neon, `neondb_owner`). Solo se usa para instalar; ni la consola ni el sensor lo usan nunca.

No hace falta escribir la URL del dueño en ningún archivo: si la variable `CHONTRY_DB_URL_ADMIN` no existe, cada orden de la herramienta la **pide sin mostrarla en pantalla**. Use la URL completa con `?sslmode=verify-full&channel_binding=require`.

### 4.1 Crear las tablas (migraciones)

```powershell
.venv\Scripts\python.exe -m herramientas.admin migrar
.venv\Scripts\python.exe -m herramientas.admin estado
```

Aplica en orden `db/001…007` y registra cada una con su SHA-256 en `chontry.schema_migraciones`. Se puede ejecutar las veces que quiera: solo aplica lo pendiente.

### 4.2 Generar la clave maestra

```powershell
.venv\Scripts\python.exe -m herramientas.admin generar-clave-maestra
```

Muestra `CHONTRY_CLAVE_MAESTRA=...` (32 bytes en base64). Esa clave cifra con AES-256-GCM las evidencias, los segundos factores y el buffer del sensor. **Debe ser la misma en el sensor y en todas las consolas.** Guárdela en un gestor de contraseñas: si se pierde, las evidencias y los segundos factores no se pueden recuperar.

### 4.3 Crear un login de BD por persona y por sensor

Cada persona tiene su propio login de PostgreSQL (así la base de datos sabe quién hace cada cosa y aplica sus permisos):

```powershell
.venv\Scripts\python.exe -m herramientas.admin crear-login ct_erick    --rol admin
.venv\Scripts\python.exe -m herramientas.admin crear-login ct_cristian --rol analista
.venv\Scripts\python.exe -m herramientas.admin crear-login ct_alexander --rol auditor
.venv\Scripts\python.exe -m herramientas.admin crear-login ct_sensor01 --rol sensor
```

Cada orden muestra **una sola vez** la contraseña generada. Entréguela a la persona por un canal seguro.

| Rol | Puede |
|---|---|
| `admin` | Todo: aprobar/rechazar/liberar contenciones, reglas, lista blanca, activos protegidos, usuarios |
| `analista` | Ver todo, gestionar alertas, **proponer** contenciones |
| `auditor` | Solo lectura, verificar la auditoría, exportar reportes y evidencias |
| `sensor` | Escribir detecciones y ejecutar contenciones aprobadas. No ve usuarios |

### 4.4 Crear las cuentas de la consola

```powershell
.venv\Scripts\python.exe -m herramientas.admin crear-usuario erick --nombre "Erick ..." --rol admin --login ct_erick
```

Muestra una **contraseña temporal**. En el primer ingreso la consola obliga a cambiarla y a activar el segundo factor (TOTP).

### 4.5 Registrar el switch y el sensor

```powershell
# Huella de la llave SSH del switch (se fija para evitar ataques de intermediario)
.venv\Scripts\python.exe -m herramientas.admin huella-ssh 10.10.10.2

.venv\Scripts\python.exe -m herramientas.admin registrar-switch sw-core-01 --ip 10.10.10.2 --fabricante cisco_ios `
    --credencial sw-core-01 --huella "SHA256:..." --puerto-span Gi1/0/48 --vlan-cuarentena 999

.venv\Scripts\python.exe -m herramientas.admin registrar-sensor sensor-01 --interfaz eth1 --filtro "not port 22" `
    --ubicacion "Cuarto técnico bloque A" --switch sw-core-01
```

`registrar-sensor` muestra el `CHONTRY_SENSOR_ID` que va en el `.env` del sensor.

### 4.6 Ajustar la configuración a su red

Los segmentos que trae la base (`10.10.10.0/24` gestión, `10.10.20.0/24` usuarios, `10.10.30.0/24` servidores, VLAN 999 cuarentena) son **ejemplos**. Ajuste a su red:

```powershell
# Servidores DHCP legítimos (si no, cualquier DHCP se considera falso)
.venv\Scripts\python.exe -m herramientas.admin configurar-regla CT-DHCP-001 --parametros '{"servidores_autorizados": ["10.0.0.1"]}'
# Contención real (por defecto es "simulado": registra los comandos sin enviarlos)
.venv\Scripts\python.exe -m herramientas.admin configurar contencion.modo_ejecucion '"real"'
```

Los segmentos se editan con SQL (`update chontry.segmentos_red ...`). Después, en la consola (Activos), marque como **protegidos** el gateway, el DNS y los controladores de dominio.

## 5. Instalar la consola en el equipo de cada persona

1. Descargar e instalar (sección 3).
2. Editar `.env`:
   ```ini
   CHONTRY_DB_URL=postgresql://ct_erick:CONTRASENA@HOST/neondb?sslmode=verify-full&channel_binding=require
   CHONTRY_CLAVE_MAESTRA=...la misma de la sección 4.2...
   ```
   Con un servidor remoto, `sslmode=verify-full` y `channel_binding=require` son **obligatorios**: la consola se niega a conectar sin ellos.
3. Abrir con doble clic en `ChonTry.bat` (o `.venv\Scripts\python.exe -m consola`).
4. Primer ingreso: usuario + contraseña temporal → nueva contraseña (12+ caracteres) → escanear el QR con Google Authenticator, Microsoft Authenticator o Aegis → código de 6 dígitos.

> La clave maestra también puede guardarse en el **keyring** del sistema en vez del `.env`: `python -c "import keyring; keyring.set_password('chontry','clave_maestra','...')"`.

## 6. Instalar el sensor

### 6.1 `.env` del sensor

```ini
CHONTRY_DB_URL=postgresql://ct_sensor01:CONTRASENA@HOST/neondb?sslmode=verify-full&channel_binding=require
CHONTRY_SENSOR_ID=...uuid de la sección 4.5...
CHONTRY_CLAVE_MAESTRA=...la misma clave maestra...
```

### 6.2 Credenciales del switch (solo para contención real)

Se guardan en el **keyring del sistema operativo**, nunca en archivos ni en la BD:

```powershell
.venv\Scripts\python.exe -m herramientas.admin guardar-credencial-switch sw-core-01 --usuario chontry
```

### 6.3 Sensor en Linux (recomendado para producción)

```bash
sudo useradd --system --home /opt/chontry chontry
sudo cp -r . /opt/chontry && sudo chown -R chontry: /opt/chontry
sudo mkdir -p /etc/chontry /var/lib/chontry && sudo chown chontry: /var/lib/chontry
sudo cp .env /etc/chontry/sensor.env && sudo chmod 600 /etc/chontry/sensor.env
sudo cp despliegue/chontry-sensor.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now chontry-sensor
journalctl -u chontry-sensor -f
```

El servicio corre como el usuario sin privilegios `chontry` y solo con las capacidades `CAP_NET_RAW` y `CAP_NET_ADMIN` (mínimo privilegio). El sensor **se niega a correr como root**.

### 6.4 Sensor en Windows

Con Npcap instalado, en una terminal de administrador:

```powershell
.venv\Scripts\python.exe -m sensor --interfaz "\Device\NPF_{GUID-DE-LA-TARJETA}"
```

Para listar las interfaces: `.venv\Scripts\python.exe -c "from scapy.all import show_interfaces; show_interfaces()"`.

### 6.5 Otros modos del sensor

| Orden | Uso |
|---|---|
| `python -m sensor --pcap archivo.pcap` | Analiza una captura guardada (pruebas, análisis forense) |
| `python -m sensor --pcap archivo.pcap --sin-bd` | Solo muestra las detecciones; no necesita base de datos |
| `python -m sensor --solo-contencion` | Solo ejecuta en el switch lo que aprueban los administradores |

## 7. Laboratorio local en 10 minutos

Para probar **todo** el sistema en un solo PC sin red real ni Neon:

1. Tener un PostgreSQL **local**. Opciones:
   - Instalar PostgreSQL 17 (`winget install PostgreSQL.PostgreSQL.17`), o
   - Descargar los binarios portables de EnterpriseDB y ejecutar `initdb` + `pg_ctl` (no requiere administrador).
2. Crear `.env.pruebas` con la URL del superusuario **local**:
   ```ini
   CHONTRY_PRUEBAS_PG_ADMIN=postgresql://postgres:CONTRASENA@localhost:5432/postgres
   ```
3. Montar el laboratorio (crea la BD `chontry_lab`, migraciones, 4 logins, 3 usuarios con TOTP, switch y sensor):
   ```powershell
   .venv\Scripts\python.exe -m herramientas.laboratorio
   ```
   Las credenciales de prueba quedan en `.env.lab` (está en `.gitignore`).
4. Generar ataques y pasarlos por el sensor:
   ```powershell
   .venv\Scripts\python.exe -m herramientas.generar_pcaps
   $env:CHONTRY_ENV = ".env.lab"
   .venv\Scripts\python.exe -m sensor --pcap pruebas\pcaps\todos_los_ataques.pcap
   ```
5. Abrir la consola con el mismo entorno: `.venv\Scripts\python.exe -m consola`. Entre con `LAB_ADMIN_USUARIO` / `LAB_ADMIN_CLAVE` de `.env.lab`; para el código TOTP ejecute
   `.venv\Scripts\python.exe -c "import pyotp,os; from comun.config import cargar_env; cargar_env(); print(pyotp.TOTP(os.environ['LAB_ADMIN_TOTP']).now())"`
   (o agregue el secreto `LAB_ADMIN_TOTP` a su app autenticadora).

Con el laboratorio montado, la prueba de integración también corre: `python -m unittest pruebas.test_integracion`.

La guía [guia_de_pruebas.md](guia_de_pruebas.md) describe qué probar y qué resultado esperar.

## 8. Solución de problemas

| Síntoma | Causa y solución |
|---|---|
| «La conexión debe usar sslmode=verify-full» | La URL remota no tiene `sslmode=verify-full&channel_binding=require`. Agréguelos |
| «La aplicación no puede usar el rol dueño» | Está usando `neondb_owner`/`postgres` en la consola o el sensor. Cree un login `ct_...` (4.3) |
| «Credenciales inválidas.» siempre | Usuario o contraseña errados, cuenta inactiva o bloqueada (5 intentos → 15 min). Un admin puede desbloquear en Usuarios |
| «Este equipo no tiene configurada la clave maestra» | Falta `CHONTRY_CLAVE_MAESTRA` en el `.env` (o es distinta a la del resto) |
| «Ese código ya se usó» | El TOTP es de un solo uso: espere el siguiente código (30 s) |
| El sensor dice «no corre como root» | Use el servicio systemd (6.3) con capacidades, o `--permitir-root` solo para diagnóstico |
| Las contenciones quedan «Aprobada (enviando)» | No hay ningún sensor corriendo que las ejecute, o falla el SSH: revise `datos/sensor.log` |
| «Fallo de conexión… huella SSH no coincide» | La llave del switch cambió o hay un equipo intermedio. Verifique y vuelva a registrar la huella |
| Errores en la consola | El usuario ve un mensaje genérico con un código; el detalle está en `datos/consola.log` (sin secretos) |
