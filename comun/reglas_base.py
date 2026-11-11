"""Reglas y configuración por defecto (copia de los datos semilla de la BD).

Se usan solo si no hay conexión ni catálogo en caché, y en el modo demostración.
La fuente de verdad es la tabla chontry.reglas_deteccion.
"""

REGLAS_BASE = [
    {"codigo": "CT-SCAN-001", "nombre": "Escaneo de puertos vertical", "categoria": "reconocimiento",
     "severidad": "media", "accion": "proponer_contencion", "mitre": "T1046",
     "parametros": {"puertos_distintos": 20, "ventana_seg": 10}},
    {"codigo": "CT-SCAN-002", "nombre": "Barrido de hosts (ping/ARP sweep)", "categoria": "reconocimiento",
     "severidad": "media", "accion": "proponer_contencion", "mitre": "T1018",
     "parametros": {"hosts_distintos": 30, "ventana_seg": 30}},
    {"codigo": "CT-SCAN-003", "nombre": "Escaneo sigiloso (NULL/FIN/Xmas)", "categoria": "reconocimiento",
     "severidad": "alta", "accion": "contener", "mitre": "T1046",
     "parametros": {"paquetes": 5, "ventana_seg": 10}},
    {"codigo": "CT-LAT-001", "nombre": "Movimiento lateral por servicios de administración",
     "categoria": "movimiento_lateral", "severidad": "alta", "accion": "contener", "mitre": "T1021",
     "parametros": {"puertos": [445, 3389, 5985, 5986, 22], "destinos_distintos": 5, "ventana_seg": 300}},
    {"codigo": "CT-AUTH-001", "nombre": "Fuerza bruta contra servicio interno", "categoria": "credenciales",
     "severidad": "alta", "accion": "proponer_contencion", "mitre": "T1110",
     "parametros": {"puertos": [22, 3389, 445, 21], "conexiones": 30, "ventana_seg": 60}},
    {"codigo": "CT-SPOOF-001", "nombre": "Suplantación ARP (ARP spoofing)", "categoria": "suplantacion",
     "severidad": "critica", "accion": "contener", "mitre": "T1557.002",
     "parametros": {"cambios_mac": 2, "ventana_seg": 60}},
    {"codigo": "CT-DHCP-001", "nombre": "Servidor DHCP no autorizado", "categoria": "suplantacion",
     "severidad": "critica", "accion": "contener", "mitre": "T1557.003",
     "parametros": {"servidores_autorizados": ["10.10.20.1"]}},
]

CONFIG_BASE = {
    "contencion.ttl_minutos": 60,
    "contencion.max_por_hora": 5,
    "contencion.modo_ejecucion": "simulado",
    "deteccion.agregacion_seg": 300,
    "auth.max_intentos": 5,
    "auth.bloqueo_minutos": 15,
    "auth.mfa_obligatorio": True,
    "sesion.duracion_minutos": 480,
    "sesion.inactividad_minutos": 15,
    "sensor.heartbeat_seg": 30,
    "sensor.metricas_seg": 10,
}
