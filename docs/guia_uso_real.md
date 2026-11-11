# Guía de uso real — detectar un escaneo y decidir qué bloquear

Esta guía lleva ChonTry de las capturas de prueba a **tráfico real**: alguien escanea la red, ChonTry lo detecta y la consola le dice qué equipo aislar. También explica cómo darle acceso a otra persona (sección 4).

> ⚠️ **Escanee solo redes y equipos propios o con autorización escrita.** En la red de la universidad, pida permiso a TI y al docente. Escanear redes ajenas puede ser un delito.

---

## 1. Prueba real en su casa (un solo PC, sin switch gestionable)

En una red doméstica no hay puerto SPAN, así que el sensor solo ve el tráfico **de su propio PC**. Basta para probar: usted escanea un equipo **suyo** (el router, su celular, otro PC) y el sensor detecta el escaneo que sale de su máquina.

### 1.1 Instalar Nmap (incluye Npcap)

Descargue Nmap para Windows desde **https://nmap.org/download.html** e instálelo. El instalador incluye **Npcap**, el controlador que permite capturar paquetes en Windows; deje marcada la opción de instalarlo.

### 1.2 Registrar su red en ChonTry

Averigüe su red con `ipconfig` (por ejemplo, IPv4 `192.168.88.205` → red `192.168.88.0/24`) y regístrela:

```powershell
.venv\Scripts\python.exe -m herramientas.admin registrar-segmento "Red de casa" --red 192.168.88.0/24 --vlan 1 --tipo usuarios
```

Sin este paso, ChonTry detecta igual, pero no sabe a qué VLAN pertenece cada equipo y no puede proponer el bloqueo (lo deja auditado como «contención imposible»).

### 1.3 Encender el sensor en vivo

Abra **PowerShell como administrador** en la carpeta `chontry`:

```powershell
# Ver las interfaces y copiar la del Wi-Fi o Ethernet (\Device\NPF_{...})
.venv\Scripts\python.exe -c "from scapy.all import show_interfaces; show_interfaces()"

$env:CHONTRY_ENV = ".env.lab"      # o deje su .env si usa Neon
.venv\Scripts\python.exe -m sensor --interfaz "\Device\NPF_{SU-GUID}" --filtro "not port 5432 and not port 443"
```

Debe decir «Capturando en … (Ctrl+C para salir)». El filtro evita analizar el tráfico de la propia base de datos y la navegación HTTPS.

### 1.4 Hacer el escaneo

En **otra** ventana de PowerShell, escanee un equipo suyo (aquí el router `192.168.88.1`):

| Prueba | Orden | Qué debería detectar ChonTry |
|---|---|---|
| Escaneo de puertos | `nmap -sS -p 1-200 192.168.88.1` | **CT-SCAN-001**, severidad media → propone contención |
| Escaneo sigiloso | `nmap -sN -p 1-50 192.168.88.1` | **CT-SCAN-003**, alta → contención automática |
| Barrido de la red | `nmap -sn 192.168.88.0/24` | **CT-SCAN-002**, media → propone contención |

### 1.5 Ver qué bloquear en la consola

1. Abra la consola (`ChonTry.bat`, o con `$env:CHONTRY_ENV=".env.lab"` si usa el laboratorio).
2. **Alertas**: aparece la detección con origen **su propio PC** (la IP desde la que escaneó), los puertos y la técnica MITRE.
3. **Cuarentena**: ahí está la respuesta a «qué bloquear».
   - *Pendiente de aprobación*: ChonTry recomienda aislar ese equipo. Revise la alerta y pulse **Aprobar y aplicar** o **Rechazar**.
   - *En cuarentena*: ya lo aisló solo (escaneo sigiloso).
   - El cuadro **Comandos para el switch** muestra exactamente qué se enviaría al switch.
4. En casa la contención es **simulada** (no hay switch gestionable): verá `[SIMULADO]` en el resultado. Nada se bloquea de verdad, pero el flujo completo funciona.
5. **Alertas → Exportar evidencia (.pcap)** guarda los paquetes del escaneo para abrirlos en Wireshark.

> Si su PC sale en Activos como **protegido**, ChonTry nunca lo aislará: es el comportamiento esperado.

## 2. Uso real en una red con switch gestionable (producción o laboratorio de la universidad)

| Paso | Qué hacer |
|---|---|
| 1. Puerto espejo | En el switch, configure un puerto **SPAN** que copie el tráfico de las VLAN de usuarios hacia el puerto del sensor (Cisco: `monitor session 1 source vlan 20` / `monitor session 1 destination interface Gi1/0/48`) |
| 2. Sensor | Un equipo Linux conectado a ese puerto, con el servicio systemd ([manual de instalación, 6.3](manual_instalacion.md#63-sensor-en-linux-recomendado-para-producción)) |
| 3. Registrar | `registrar-switch` (con `--puerto-span` y la huella SSH), `registrar-sensor`, `registrar-segmento` por cada VLAN, y las credenciales del switch en el keyring |
| 4. Proteger | En la consola → **Activos**, marque como protegidos el gateway, los DNS y los controladores de dominio |
| 5. Lista blanca | Agregue los escáneres autorizados de TI |
| 6. Activar la contención real | `python -m herramientas.admin configurar contencion.modo_ejecucion '"real"'` — **solo después** de probar en GNS3/EVE-NG o en un switch de laboratorio |

Desde ese momento, cuando alguien escanee o se mueva lateralmente, el puerto del switch donde está conectado pasa a la **VLAN 999 de cuarentena**: automáticamente en los casos de alta confianza, o cuando un administrador aprueba la propuesta.

## 3. Cómo decidir qué bloquear

| Si la alerta es… | Lo usual |
|---|---|
| **Crítica** (ARP spoofing, DHCP falso) | Aislar ya. Está interceptando o desviando el tráfico de otros |
| **Alta** (escaneo sigiloso, movimiento lateral, fuerza bruta) | Aislar y revisar el equipo: suele ser malware o un intruso |
| **Media** (escaneo, barrido) | Revisar primero: puede ser un técnico autorizado. Si lo es, marque **Falso positivo** y agréguelo a la **Lista blanca** |
| El origen es un servidor o el gateway | Nunca se aísla automáticamente (activo protegido): investigue sin cortar el servicio |

## 4. Cómo accede otra persona (por ejemplo, su compañero)

Las credenciales **nunca** van en GitHub: el repositorio solo trae `.env.example` vacío. Cada persona recibe las suyas por un canal seguro. Hay dos formas:

### Opción A — Su compañero monta su propio laboratorio (no le pasa ninguna credencial)

Lo más sencillo para probar:

1. Usted lo invita al repositorio: GitHub → *Settings → Collaborators → Add people*.
2. Él clona el repositorio, ejecuta `instalar.bat` e instala PostgreSQL en su PC.
3. Ejecuta `python -m herramientas.laboratorio`. El script **genera sus propias credenciales de prueba** en su `.env.lab`.
4. Con `python -m herramientas.acceso_lab` ve sus usuarios y los códigos de verificación.

Usted no le entrega nada: cada laboratorio tiene sus propios usuarios y su propia clave maestra.

### Opción B — Su compañero entra a la base de datos real (Neon)

Usted, como administrador de la base de datos, le crea el acceso:

```powershell
.venv\Scripts\python.exe -m herramientas.admin crear-login ct_cristian --rol analista
.venv\Scripts\python.exe -m herramientas.admin crear-usuario cristian --nombre "Cristian David Meneses Rueda" --rol analista --login ct_cristian
```

Esos comandos muestran **una sola vez**:
- la **contraseña del login de base de datos** (`ct_cristian`), y
- la **contraseña temporal** de la consola.

Entréguele, **por un canal seguro** (en persona o con un gestor de contraseñas; no por un chat ni por correo en texto plano):

| Qué | Dónde lo pone él |
|---|---|
| URL con el login `ct_cristian` y su contraseña | `CHONTRY_DB_URL` en su `.env` |
| La **clave maestra** del sistema | `CHONTRY_CLAVE_MAESTRA` en su `.env` |
| Su usuario de la consola y la contraseña temporal | La escribe al iniciar sesión |

En su primer ingreso, la consola le obliga a **cambiar la contraseña** y a **registrar su propio segundo factor** escaneando un QR con su celular. Desde ese momento, ni usted conoce su contraseña.

Para quitarle el acceso: consola → **Usuarios** → *Desactivar* y *Cerrar sus sesiones*. Para borrar del todo su login de base de datos, use `drop role ct_cristian` como dueño de la BD.
