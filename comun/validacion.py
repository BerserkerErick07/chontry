"""Validación positiva (lista blanca) de entradas y comandos del switch.

Corrige el hallazgo H2 de la Clase 3 (inyección de comandos). Aplica las mismas
reglas que los CHECK de la BD (migraciones 002 y 003): la app rechaza primero y
la BD es la última línea de defensa.

Se usa ``fullmatch`` y no ``match`` con ``$``: en Python ``$`` también acepta
un salto de línea final, justo lo que usaría un atacante (``Gi1/0/1\\nreload``).

Normas: OWASP ASVS V5 5.3 y 5.5 · NIST SSDF PW.7.
"""
import ipaddress
import re

_ENTERO = re.compile(r"[0-9]{1,5}")
_INTERFAZ_SWITCH = re.compile(r"([A-Za-z][A-Za-z-]{0,24})?[0-9]{1,4}(/[0-9]{1,4}){0,3}(\.[0-9]{1,4})?")
_INTERFAZ_CAPTURA = re.compile(r"[A-Za-z0-9._-]{1,15}|\\Device\\NPF_\{[0-9A-Fa-f-]{36}\}")
_FILTRO_BPF = re.compile(r"[A-Za-z0-9 ().:/!=<>\[\]-]{1,512}")

FABRICANTES = frozenset({
    "cisco_ios", "cisco_nxos", "hp_procurve", "aruba_os", "juniper_junos", "mikrotik_routeros",
})

# Comandos de cuarentena por fabricante. Solo se rellenan valores ya validados;
# nunca se concatena texto libre. Netmiko los envía como lista, sin shell.
_PLANTILLAS_CUARENTENA = {
    "cisco_ios": ("interface {interfaz}", "switchport access vlan {vlan}"),
    "cisco_nxos": ("interface {interfaz}", "switchport access vlan {vlan}"),
    "hp_procurve": ("vlan {vlan} untagged {interfaz}",),
}


class EntradaInvalida(ValueError):
    """La entrada no cumple la lista blanca. El mensaje es apto para el usuario."""


def validar_ip(valor: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(valor, str) or len(valor) > 45:
        raise EntradaInvalida("Dirección IP inválida")
    try:
        return ipaddress.ip_address(valor)
    except ValueError:
        raise EntradaInvalida("Dirección IP inválida") from None


def _validar_entero(valor: int | str, minimo: int, maximo: int, nombre: str) -> int:
    if isinstance(valor, str):
        if not _ENTERO.fullmatch(valor):
            raise EntradaInvalida(f"{nombre} inválido")
        valor = int(valor)
    if isinstance(valor, bool) or not isinstance(valor, int) or not minimo <= valor <= maximo:
        raise EntradaInvalida(f"{nombre} fuera de rango ({minimo}-{maximo})")
    return valor


def validar_puerto(valor: int | str) -> int:
    return _validar_entero(valor, 1, 65535, "Puerto")


def validar_vlan(valor: int | str) -> int:
    return _validar_entero(valor, 1, 4094, "VLAN")


def _validar_patron(valor: str, patron: re.Pattern, nombre: str) -> str:
    if not isinstance(valor, str) or not patron.fullmatch(valor):
        raise EntradaInvalida(f"{nombre} inválido")
    return valor


def validar_interfaz_switch(valor: str) -> str:
    return _validar_patron(valor, _INTERFAZ_SWITCH, "Nombre de interfaz del switch")


def validar_interfaz_captura(valor: str) -> str:
    return _validar_patron(valor, _INTERFAZ_CAPTURA, "Interfaz de captura")


def validar_filtro_bpf(valor: str) -> str:
    return _validar_patron(valor, _FILTRO_BPF, "Filtro BPF")


def validar_fabricante(valor: str) -> str:
    if valor not in FABRICANTES:
        raise EntradaInvalida("Fabricante no soportado")
    return valor


def comandos_cuarentena(fabricante: str, interfaz: str, vlan: int | str) -> list[str]:
    """Comandos para mover un puerto a la VLAN de cuarentena, ya validados."""
    plantilla = _PLANTILLAS_CUARENTENA.get(validar_fabricante(fabricante))
    if plantilla is None:
        raise EntradaInvalida("Este fabricante todavía no tiene plantilla de cuarentena")
    valores = {"interfaz": validar_interfaz_switch(interfaz), "vlan": validar_vlan(vlan)}
    return [linea.format(**valores) for linea in plantilla]
