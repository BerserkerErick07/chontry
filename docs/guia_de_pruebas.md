# Guía de pruebas — qué probar y qué debe pasar

Para el compañero que descarga el proyecto y para quien lo audite. Requiere el **laboratorio local** del [manual de instalación, sección 7](manual_instalacion.md#7-laboratorio-local-en-10-minutos).

> En PowerShell, antes de cada prueba: `$env:CHONTRY_ENV = ".env.lab"`

## A. Pruebas automáticas

```powershell
.venv\Scripts\python.exe -m unittest discover -s pruebas -t . -v
.venv\Scripts\bandit.exe -r comun consola sensor herramientas
.venv\Scripts\python.exe herramientas\buscar_secretos.py
```

**Resultado esperado:** 55 pruebas OK (8 de integración si hay PostgreSQL de pruebas), Bandit sin hallazgos medios ni altos y 0 secretos reales.

## B. Detección

| # | Prueba | Orden | Resultado esperado |
|---|---|---|---|
| B1 | Tráfico normal | `python -m sensor --pcap pruebas\pcaps\trafico_normal.pcap --sin-bd` | Ninguna detección |
| B2 | Cada ataque | `python -m sensor --pcap pruebas\pcaps\<escenario>.pcap --sin-bd` con `escaneo_puertos`, `barrido_hosts`, `escaneo_sigiloso`, `movimiento_lateral`, `fuerza_bruta`, `arp_spoofing`, `dhcp_falso` | Se dispara su regla (CT-SCAN-001, 002, 003, CT-LAT-001, CT-AUTH-001, CT-SPOOF-001, CT-DHCP-001) |
| B3 | Todo junto, con BD | `python -m sensor --pcap pruebas\pcaps\todos_los_ataques.pcap` | Termina con `alertas: 8`, `escritas` > 0, `descartadas: 0` |
| B4 | Captura propia | Capture con Wireshark mientras hace `nmap -sS` a un equipo de prueba **propio** y pásela con `--pcap` | CT-SCAN-001 |

## C. Consola y permisos

Entre con los usuarios de `.env.lab` (contraseña + código TOTP).

| # | Prueba | Resultado esperado |
|---|---|---|
| C1 | Contraseña errada 5 veces con `auditor.lab` | Siempre «Credenciales inválidas.»; a la 6.ª, aunque sea correcta, sigue denegado (bloqueo 15 min) |
| C2 | Usuario inexistente | El mismo mensaje «Credenciales inválidas.» |
| C3 | Reutilizar el mismo código TOTP en dos inicios seguidos | El segundo: «Ese código ya se usó» |
| C4 | Analista → Cuarentena | Aprobar / Rechazar / Liberar deshabilitados |
| C5 | Analista → Contención manual con `10.10.20.999` o `Gi1/0/1; reload` | Campo en rojo y rechazo |
| C6 | Analista → Contención manual a `10.10.20.10`, puerto `Gi1/0/48` | Rechazada: es el puerto SPAN |
| C7 | Analista → Contención manual a `10.10.30.10` | Rechazada: activo protegido |
| C8 | Admin aprueba una propuesta y luego `python -m sensor --solo-contencion` (Ctrl+C tras unos segundos) | La contención pasa a «En cuarentena» con salida `[SIMULADO…]` |
| C9 | Admin → Liberar host + sensor `--solo-contencion` | Pasa a «Liberada» |
| C10 | Alertas → Exportar evidencia | Se guarda un `.pcap` que abre en Wireshark |
| C11 | Lista blanca: agregar `10.10.20.66` para CT-SCAN-001 y repetir B3 | Esa alerta ya no se genera |
| C12 | Reportes → Generar HTML y CSV | Archivos guardados; aparecen en la tabla con su SHA-256 |
| C13 | Auditoría → Verificar integridad | «Cadena íntegra» |
| C14 | Sin tocar la consola 15 min | Se cierra la sesión por inactividad |
| C15 | Usuarios (admin) → Cerrar sus sesiones a otro usuario conectado | Su consola se cierra en segundos |

## D. Seguridad de la base de datos (con `psql` o el SQL Editor)

Conectado con un login de **analista**:

```sql
update chontry.usuarios set rol = 'admin';                         -- ERROR: permiso denegado
select password_hash from chontry.usuarios;                        -- ERROR: permiso denegado
update chontry.contenciones set estado = 'aprobada';               -- ERROR: un analista no puede aprobar
```

Conectado como **dueño**:

```sql
update chontry.auditoria set accion = 'x' where id = 1;            -- ERROR: solo anexado
delete from chontry.auditoria where id = 1;                        -- ERROR: solo anexado
select * from chontry.verificar_auditoria();                       -- 0 filas
```

## E. Resiliencia

| # | Prueba | Resultado esperado |
|---|---|---|
| E1 | Apague PostgreSQL y corra B3 | El sensor detecta igual y dice «se guarda en el buffer local» |
| E2 | Encienda PostgreSQL y corra el sensor otra vez (`--solo-contencion` unos segundos) | «Lote del buffer sincronizado»; las alertas de E1 aparecen en la consola |
| E3 | Con la consola abierta, apague PostgreSQL | Aviso naranja de reconexión; al volver, se quita solo |
