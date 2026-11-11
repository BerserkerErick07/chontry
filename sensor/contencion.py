"""Ejecución de la contención en el switch (VLAN de cuarentena).

Modo "simulado": registra los comandos que se enviarían, sin conectarse.
Modo "real": SSH con Netmiko, con la huella de la llave del switch verificada
ANTES de autenticarse (evita entregar la contraseña a un equipo intermedio) y
credenciales tomadas del keyring del sistema operativo, nunca de la BD.
Los comandos salen de plantillas fijas con valores validados (comun.validacion).
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import re

from comun.validacion import EntradaInvalida, comandos_cuarentena, validar_interfaz_switch

log = logging.getLogger("chontry.sensor")
_INTERFAZ_EN_TABLA = re.compile(r"^\s*\d+\s+[0-9a-f.:]+\s+\S+\s+(\S+)\s*$", re.IGNORECASE | re.MULTILINE)


class ErrorContencion(Exception):
    """No se pudo ejecutar la contención en el switch."""


def huella_de_llave(llave_bytes: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(llave_bytes).digest()).decode().rstrip("=")


class Ejecutor:
    def __init__(self, modo: str = "simulado"):
        if modo not in ("simulado", "real"):
            raise ValueError("modo de ejecución inválido")
        self.modo = modo

    # ----------------------------------------------------------- comandos
    @staticmethod
    def comandos(switch: dict, puerto: str, vlan: int) -> list[str]:
        return comandos_cuarentena(switch["fabricante"], puerto, vlan)

    def aplicar(self, switch: dict, puerto: str, vlan_destino: int) -> tuple[bool, str]:
        return self._ejecutar(switch, self.comandos(switch, puerto, vlan_destino))

    def revertir(self, switch: dict, puerto: str, vlan_origen: int) -> tuple[bool, str]:
        return self._ejecutar(switch, self.comandos(switch, puerto, vlan_origen))

    def resolver_puerto(self, switch: dict, mac: str) -> str | None:
        """Puerto del switch donde está conectada una MAC."""
        if self.modo == "simulado":
            # Laboratorio sin switch: puerto determinista para poder demostrar el flujo completo
            return f"Gi1/0/{int(hashlib.sha256(mac.encode()).hexdigest(), 16) % 48 + 1}"
        if not switch["fabricante"].startswith("cisco"):
            return None
        mac_cisco = mac.replace(":", "").lower()
        mac_cisco = ".".join(mac_cisco[i:i + 4] for i in range(0, 12, 4))
        try:
            with self._conectar(switch) as conexion:
                salida = conexion.send_command(f"show mac address-table address {mac_cisco}")
        except Exception as exc:  # noqa: BLE001 - se registra y la contención queda como imposible
            log.error("No se pudo consultar la tabla MAC de %s: %s", switch["nombre"], type(exc).__name__)
            return None
        coincidencia = _INTERFAZ_EN_TABLA.search(salida)
        if not coincidencia:
            return None
        try:
            return validar_interfaz_switch(coincidencia.group(1))
        except EntradaInvalida:
            return None

    # ---------------------------------------------------------- ejecución
    def _ejecutar(self, switch: dict, comandos: list[str]) -> tuple[bool, str]:
        if self.modo == "simulado":
            return True, "[SIMULADO: no se envió al switch]\n" + "\n".join(comandos)
        try:
            with self._conectar(switch) as conexion:
                salida = conexion.send_config_set(comandos)
                return True, salida[-2000:]
        except ErrorContencion as exc:
            return False, str(exc)
        except Exception as exc:  # noqa: BLE001 - se devuelve un mensaje sin datos sensibles
            log.error("Fallo al ejecutar en %s: %s", switch["nombre"], exc)
            return False, f"Fallo de conexión o de ejecución en el switch ({type(exc).__name__})"

    def _verificar_huella(self, switch: dict) -> None:
        import paramiko
        if not switch.get("huella"):
            raise ErrorContencion("El switch no tiene huella SSH registrada: no se envían credenciales")
        transporte = paramiko.Transport((switch["ip"], int(switch.get("puerto_ssh") or 22)))
        try:
            transporte.start_client(timeout=10)
            huella = huella_de_llave(transporte.get_remote_server_key().asbytes())
        finally:
            transporte.close()
        if huella != switch["huella"]:
            raise ErrorContencion(f"La huella SSH de {switch['nombre']} no coincide: posible equipo intermedio (MITM)")

    def _conectar(self, switch: dict):
        import keyring
        from netmiko import ConnectHandler
        self._verificar_huella(switch)
        guardado = keyring.get_password("chontry-switch", switch["credencial_ref"])
        if not guardado:
            raise ErrorContencion(f"No hay credenciales en el keyring para {switch['credencial_ref']}")
        credencial = json.loads(guardado)
        return ConnectHandler(device_type=switch["fabricante"], host=switch["ip"],
                              port=int(switch.get("puerto_ssh") or 22), username=credencial["usuario"],
                              password=credencial["clave"], timeout=15, conn_timeout=15)
