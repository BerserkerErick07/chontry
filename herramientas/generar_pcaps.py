"""Genera capturas .pcap de laboratorio con tráfico normal y ataques internos.

Sirven para probar el sensor de punta a punta sin switch ni puerto SPAN:
    python -m herramientas.generar_pcaps            (escribe en pruebas/pcaps/)
    python -m sensor --pcap pruebas/pcaps/todos_los_ataques.pcap

Red de laboratorio (la de los segmentos de ejemplo de la BD):
    10.10.20.0/24 usuarios (gateway 10.10.20.1) · 10.10.30.0/24 servidores
"""
import random
import sys
import time
from pathlib import Path

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

RAIZ = Path(__file__).resolve().parent.parent
MAC_GATEWAY = "00:1a:2b:00:00:01"
GATEWAY = "10.10.20.1"


def mac_de(ip: str) -> str:
    a, b, c, d = (int(x) for x in ip.split("."))
    return f"02:00:{a:02x}:{b:02x}:{c:02x}:{d:02x}"


class Reloj:
    def __init__(self, inicio: float):
        self.t = inicio

    def __call__(self, paso: float = 0.01) -> float:
        self.t += paso
        return self.t


def _p(paquete, ts):
    paquete.time = ts
    return paquete


def trafico_normal(reloj: Reloj, n: int = 120, semilla: int = 7) -> list:
    """Navegación y uso normal: handshakes completos, DNS y ARP legítimo del gateway."""
    azar = random.Random(semilla)
    paquetes = []
    for _ in range(n):
        cliente = f"10.10.20.{azar.randint(10, 40)}"
        servidor = f"10.10.30.{azar.choice([11, 12, 15])}"
        puerto = azar.choice([80, 443, 53])
        sport = azar.randint(40000, 60000)
        eth = Ether(src=mac_de(cliente), dst=mac_de(servidor))
        paquetes.append(_p(eth / IP(src=cliente, dst=servidor) / TCP(sport=sport, dport=puerto, flags="S"), reloj(0.2)))
        paquetes.append(_p(Ether(src=mac_de(servidor), dst=mac_de(cliente)) /
                           IP(src=servidor, dst=cliente) / TCP(sport=puerto, dport=sport, flags="SA"), reloj(0.01)))
        paquetes.append(_p(eth / IP(src=cliente, dst=servidor) / TCP(sport=sport, dport=puerto, flags="A"), reloj(0.01)))
        if azar.random() < 0.1:
            paquetes.append(_p(Ether(src=MAC_GATEWAY, dst=mac_de(cliente)) /
                               ARP(op=2, psrc=GATEWAY, hwsrc=MAC_GATEWAY, pdst=cliente, hwdst=mac_de(cliente)),
                               reloj(0.05)))
    return paquetes


def escaneo_puertos(reloj, atacante="10.10.20.66", victima="10.10.30.15") -> list:
    eth = Ether(src=mac_de(atacante), dst=mac_de(victima))
    return [_p(eth / IP(src=atacante, dst=victima) / TCP(sport=51000 + p, dport=p, flags="S"), reloj(0.02))
            for p in range(1, 101)]


def barrido_hosts(reloj, atacante="10.10.20.77") -> list:
    icmp = [_p(Ether(src=mac_de(atacante), dst=mac_de(f"10.10.20.{n}")) / IP(src=atacante, dst=f"10.10.20.{n}") /
               ICMP(type=8), reloj(0.05)) for n in range(2, 40)]
    arp = [_p(Ether(src=mac_de(atacante), dst="ff:ff:ff:ff:ff:ff") /
              ARP(op=1, psrc=atacante, hwsrc=mac_de(atacante), pdst=f"10.10.30.{n}"), reloj(0.05))
           for n in range(2, 40)]
    return icmp + arp


def escaneo_sigiloso(reloj, atacante="10.10.20.88", victima="10.10.30.12") -> list:
    eth = Ether(src=mac_de(atacante), dst=mac_de(victima))
    banderas = ["", "F", "FPU"] * 4
    return [_p(eth / IP(src=atacante, dst=victima) / TCP(sport=40000 + i, dport=20 + i, flags=f), reloj(0.1))
            for i, f in enumerate(banderas)]


def movimiento_lateral(reloj, atacante="10.10.20.99") -> list:
    paquetes = []
    for n in range(11, 18):
        victima = f"10.10.30.{n}"
        for puerto in (445, 3389):
            paquetes.append(_p(Ether(src=mac_de(atacante), dst=mac_de(victima)) /
                               IP(src=atacante, dst=victima) / TCP(sport=50000 + n, dport=puerto, flags="S"), reloj(1.5)))
    return paquetes


def fuerza_bruta(reloj, atacante="10.10.20.55", victima="10.10.30.20") -> list:
    eth = Ether(src=mac_de(atacante), dst=mac_de(victima))
    return [_p(eth / IP(src=atacante, dst=victima) / TCP(sport=30000 + i, dport=22, flags="S"), reloj(0.8))
            for i in range(45)]


def arp_spoofing(reloj, atacante="10.10.20.44") -> list:
    mac_atacante = mac_de(atacante)
    paquetes = [_p(Ether(src=mac_atacante, dst=mac_de("10.10.30.11")) / IP(src=atacante, dst="10.10.30.11") /
                   TCP(sport=45000, dport=443, flags="S"), reloj(0.1))]
    for i in range(6):
        mac = mac_atacante if i % 2 == 0 else MAC_GATEWAY
        paquetes.append(_p(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
                           ARP(op=2, psrc=GATEWAY, hwsrc=mac, pdst="10.10.20.255"), reloj(2)))
    return paquetes


def dhcp_falso(reloj, falso="10.10.20.250") -> list:
    def oferta(servidor, mac):
        return (Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / IP(src=servidor, dst="255.255.255.255") /
                UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr="10.10.20.150", siaddr=servidor, xid=0x1234) /
                DHCP(options=[("message-type", 2), ("server_id", servidor), "end"]))
    return [_p(oferta(GATEWAY, MAC_GATEWAY), reloj(1)), _p(oferta(falso, mac_de(falso)), reloj(1))]


def protegido_lateral(reloj) -> list:
    """El DNS/DC (activo protegido en las pruebas) hace conexiones de administración: no se debe aislar."""
    return movimiento_lateral(reloj, atacante="10.10.30.10")


ESCENARIOS = {
    "trafico_normal": trafico_normal,
    "escaneo_puertos": escaneo_puertos,
    "barrido_hosts": barrido_hosts,
    "escaneo_sigiloso": escaneo_sigiloso,
    "movimiento_lateral": movimiento_lateral,
    "fuerza_bruta": fuerza_bruta,
    "arp_spoofing": arp_spoofing,
    "dhcp_falso": dhcp_falso,
    "activo_protegido": protegido_lateral,
}


def generar(carpeta: Path, inicio: float | None = None) -> dict[str, int]:
    carpeta.mkdir(parents=True, exist_ok=True)
    inicio = inicio or time.time() - 600
    resultado = {}
    todos = []
    for nombre, fabrica in ESCENARIOS.items():
        paquetes = fabrica(Reloj(inicio))
        wrpcap(str(carpeta / f"{nombre}.pcap"), paquetes)
        resultado[nombre] = len(paquetes)
    reloj = Reloj(inicio)
    for nombre, fabrica in ESCENARIOS.items():
        todos += trafico_normal(reloj, 20, semilla=len(todos)) + fabrica(reloj)
    wrpcap(str(carpeta / "todos_los_ataques.pcap"), todos)
    resultado["todos_los_ataques"] = len(todos)
    return resultado


if __name__ == "__main__":
    destino = Path(sys.argv[1]) if len(sys.argv) > 1 else RAIZ / "pruebas" / "pcaps"
    for archivo, cantidad in generar(destino).items():
        print(f"  {archivo + '.pcap':28} {cantidad:5} paquetes")
