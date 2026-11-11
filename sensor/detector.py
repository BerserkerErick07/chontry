"""Motor de reglas: convierte paquetes en detecciones con ventanas deslizantes.

Cada regla cuenta eventos por clave (origen, destino…) dentro de su ventana de
tiempo. Al llegar al umbral se emite una Detección y la ventana se vacía, así una
ráfaga produce un evento y no uno por paquete. El tiempo es el del paquete, por
eso una captura .pcap se analiza igual que el tráfico en vivo.
"""
from __future__ import annotations

import ipaddress
import logging
from collections import deque
from dataclasses import dataclass, field

from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

log = logging.getLogger("chontry.sensor")

SYN, ACK, FIN, PSH, URG = 0x02, 0x10, 0x01, 0x08, 0x20
MAX_PAQUETES_EVIDENCIA = 20


@dataclass
class Deteccion:
    codigo: str
    ts: float
    ip_origen: str
    mac_origen: str | None
    destinos: set[str] = field(default_factory=set)
    puertos: set[int] = field(default_factory=set)
    protocolo: str = "tcp"
    descripcion: str = ""
    paquetes: list = field(default_factory=list)


class Ventana:
    """Eventos (ts, valor, paquete) dentro de los últimos `segundos`."""
    __slots__ = ("segundos", "eventos")

    def __init__(self, segundos: float):
        self.segundos = segundos
        self.eventos: deque = deque()

    def agregar(self, ts: float, valor, paquete) -> None:
        self.eventos.append((ts, valor, paquete))
        while self.eventos and ts - self.eventos[0][0] > self.segundos:
            self.eventos.popleft()

    def distintos(self) -> set:
        return {valor for _, valor, _ in self.eventos}

    def paquetes(self) -> list:
        return [p for _, _, p in list(self.eventos)[-MAX_PAQUETES_EVIDENCIA:]]

    def ultimo(self) -> float:
        return self.eventos[-1][0] if self.eventos else 0.0

    def __len__(self) -> int:
        return len(self.eventos)


def _es_unicast(mac: str | None) -> bool:
    return bool(mac) and not (int(mac.split(":")[0], 16) & 1)


def _es_ip_util(ip: str) -> bool:
    try:
        direccion = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (direccion.is_multicast or direccion.is_unspecified or ip.endswith(".255"))


class Detector:
    def __init__(self, reglas: dict[str, dict], arp_conocidas: dict[str, str] | None = None):
        """reglas: código -> {"habilitada": bool, "parametros": dict}.
        arp_conocidas: ip -> MAC legítima de los activos protegidos (gateway, DNS…)."""
        self.reglas = reglas
        self.arp_conocidas = {ip: mac.lower() for ip, mac in (arp_conocidas or {}).items()}
        self._ventanas: dict[tuple, Ventana] = {}
        self._arp_primero: dict[str, str] = {}     # ip -> primera MAC vista (la legítima)
        self._arp_actual: dict[str, str] = {}      # ip -> última MAC anunciada
        self.ip_de_mac: dict[str, str] = {}        # mac -> ip propia (aprendida de su tráfico)
        self._ultimo_dhcp: dict[str, float] = {}
        self._paquetes = 0
        self._aviso_dhcp = False

    # ----------------------------------------------------------- utilidades
    def actualizar_reglas(self, reglas: dict[str, dict], arp_conocidas: dict[str, str] | None = None) -> None:
        self.reglas = reglas
        if arp_conocidas is not None:
            self.arp_conocidas = {ip: mac.lower() for ip, mac in arp_conocidas.items()}

    def _param(self, codigo: str, nombre: str, defecto):
        regla = self.reglas.get(codigo)
        return (regla or {}).get("parametros", {}).get(nombre, defecto)

    def _activa(self, codigo: str) -> bool:
        regla = self.reglas.get(codigo)
        return bool(regla and regla.get("habilitada", True))

    def _ventana(self, clave: tuple, segundos: float) -> Ventana:
        ventana = self._ventanas.get(clave)
        if ventana is None or ventana.segundos != segundos:
            ventana = self._ventanas[clave] = Ventana(segundos)
        return ventana

    def _purgar(self, ahora: float) -> None:
        viejas = [k for k, v in self._ventanas.items() if ahora - v.ultimo() > v.segundos]
        for clave in viejas:
            del self._ventanas[clave]

    # ----------------------------------------------------------- análisis
    def procesar(self, pkt) -> list[Deteccion]:
        self._paquetes += 1
        ts = float(pkt.time)
        if self._paquetes % 5000 == 0:
            self._purgar(ts)
        mac = pkt[Ether].src if pkt.haslayer(Ether) else None
        detecciones: list[Deteccion] = []

        if pkt.haslayer(ARP):
            detecciones += self._arp(pkt, ts)
        if pkt.haslayer(IP):
            ip = pkt[IP]
            if _es_unicast(mac) and _es_ip_util(ip.src):
                self.ip_de_mac[mac] = ip.src
            if pkt.haslayer(TCP):
                detecciones += self._tcp(pkt, ts, ip.src, ip.dst, mac)
            elif pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
                detecciones += self._barrido(pkt, ts, ip.src, ip.dst, mac, "icmp")
            if pkt.haslayer(BOOTP) and pkt.haslayer(UDP) and pkt[UDP].sport == 67:
                detecciones += self._dhcp(pkt, ts, ip.src, mac)
        return detecciones

    def _tcp(self, pkt, ts, src, dst, mac) -> list[Deteccion]:
        flags = int(pkt[TCP].flags)
        dport = int(pkt[TCP].dport)
        salida = []
        es_syn = (flags & (SYN | ACK)) == SYN
        if es_syn and self._activa("CT-SCAN-001"):
            v = self._ventana(("CT-SCAN-001", src, dst), self._param("CT-SCAN-001", "ventana_seg", 10))
            v.agregar(ts, dport, pkt)
            if len(v.distintos()) >= self._param("CT-SCAN-001", "puertos_distintos", 20):
                salida.append(Deteccion("CT-SCAN-001", ts, src, mac, {dst}, set(v.distintos()), "tcp",
                                        f"SYN a {len(v.distintos())} puertos distintos de {dst}", v.paquetes()))
                v.eventos.clear()
        xmas = (flags & (FIN | PSH | URG)) == (FIN | PSH | URG) and not flags & (SYN | ACK)
        sigiloso = flags == 0 or flags == FIN or xmas
        if sigiloso and self._activa("CT-SCAN-003"):
            v = self._ventana(("CT-SCAN-003", src), self._param("CT-SCAN-003", "ventana_seg", 10))
            v.agregar(ts, (dst, dport), pkt)
            if len(v) >= self._param("CT-SCAN-003", "paquetes", 5):
                destinos = {d for d, _ in v.distintos()}
                puertos = {p for _, p in v.distintos()}
                salida.append(Deteccion("CT-SCAN-003", ts, src, mac, destinos, puertos, "tcp",
                                        f"{len(v)} paquetes TCP con banderas NULL/FIN/Xmas", v.paquetes()))
                v.eventos.clear()
        if es_syn and self._activa("CT-LAT-001") and dport in self._param("CT-LAT-001", "puertos", [445, 3389, 5985, 5986, 22]):
            v = self._ventana(("CT-LAT-001", src), self._param("CT-LAT-001", "ventana_seg", 300))
            v.agregar(ts, dst, pkt)
            if len(v.distintos()) >= self._param("CT-LAT-001", "destinos_distintos", 5):
                salida.append(Deteccion("CT-LAT-001", ts, src, mac, set(v.distintos()),
                                        {int(p[TCP].dport) for p in v.paquetes()}, "tcp",
                                        f"Conexiones de administración remota a {len(v.distintos())} hosts internos",
                                        v.paquetes()))
                v.eventos.clear()
        if es_syn and self._activa("CT-AUTH-001") and dport in self._param("CT-AUTH-001", "puertos", [22, 3389, 445, 21]):
            v = self._ventana(("CT-AUTH-001", src, dst, dport), self._param("CT-AUTH-001", "ventana_seg", 60))
            v.agregar(ts, None, pkt)
            if len(v) >= self._param("CT-AUTH-001", "conexiones", 30):
                salida.append(Deteccion("CT-AUTH-001", ts, src, mac, {dst}, {dport}, "tcp",
                                        f"{len(v)} intentos de conexión a {dst}:{dport}", v.paquetes()))
                v.eventos.clear()
        return salida

    def _barrido(self, pkt, ts, src, dst, mac, protocolo) -> list[Deteccion]:
        if not self._activa("CT-SCAN-002"):
            return []
        v = self._ventana(("CT-SCAN-002", src), self._param("CT-SCAN-002", "ventana_seg", 30))
        v.agregar(ts, dst, pkt)
        if len(v.distintos()) >= self._param("CT-SCAN-002", "hosts_distintos", 30):
            deteccion = Deteccion("CT-SCAN-002", ts, src, mac, set(v.distintos()), set(), protocolo,
                                  f"Sondeo {protocolo.upper()} a {len(v.distintos())} hosts", v.paquetes())
            v.eventos.clear()
            return [deteccion]
        return []

    def _arp(self, pkt, ts) -> list[Deteccion]:
        arp = pkt[ARP]
        psrc, hwsrc = arp.psrc, arp.hwsrc
        if arp.op == 1:   # who-has
            if _es_unicast(hwsrc) and _es_ip_util(psrc):
                self.ip_de_mac.setdefault(hwsrc, psrc)
            # Sondeo ARP con origen sin dirección (ARP probe, RFC 5227): no es un barrido
            sondeo = not _es_ip_util(psrc)
            return [] if sondeo else self._barrido(pkt, ts, psrc, arp.pdst, hwsrc, "arp")
        if arp.op != 2 or not _es_unicast(hwsrc):
            return []
        primero = self._arp_primero.setdefault(psrc, self.arp_conocidas.get(psrc, hwsrc))
        anterior = self._arp_actual.get(psrc, hwsrc)
        self._arp_actual[psrc] = hwsrc
        if hwsrc == primero:
            self.ip_de_mac.setdefault(hwsrc, psrc)
        if anterior == hwsrc or not self._activa("CT-SPOOF-001"):
            return []
        v = self._ventana(("CT-SPOOF-001", psrc), self._param("CT-SPOOF-001", "ventana_seg", 60))
        v.agregar(ts, hwsrc, pkt)
        if len(v) < self._param("CT-SPOOF-001", "cambios_mac", 2):
            return []
        atacante = self._culpable(psrc, primero, [e[1] for e in v.eventos])
        ip_atacante = self.ip_de_mac.get(atacante, psrc)
        if atacante == primero:
            primero = next((m for m in reversed([e[1] for e in v.eventos]) if m != atacante), primero)
        v.eventos.clear()
        return [Deteccion("CT-SPOOF-001", ts, ip_atacante, atacante, {psrc}, set(), "arp",
                          f"La MAC {atacante} se anuncia como {psrc} (MAC legítima {primero})", [pkt])]

    def _culpable(self, ip: str, primero: str, anunciadas: list[str]) -> str:
        """Quién suplanta a `ip`. En orden: la MAC registrada del activo protegido manda; si una MAC
        ya usa otra IP propia, es el atacante; si no, la que difiere de la primera vista."""
        candidatas = list(dict.fromkeys(anunciadas + [primero]))
        legitima = self.arp_conocidas.get(ip)
        if legitima:
            return next((m for m in reversed(candidatas) if m != legitima), anunciadas[-1])
        con_otra_ip = [m for m in candidatas if self.ip_de_mac.get(m) not in (None, ip)]
        if len(con_otra_ip) == 1:
            return con_otra_ip[0]
        return next((m for m in reversed(anunciadas) if m != primero), anunciadas[-1])

    def _dhcp(self, pkt, ts, servidor, mac) -> list[Deteccion]:
        if not self._activa("CT-DHCP-001"):
            return []
        opciones = dict(o for o in pkt[DHCP].options if isinstance(o, tuple) and len(o) == 2) if pkt.haslayer(DHCP) else {}
        if pkt[BOOTP].op != 2 or opciones.get("message-type") not in (2, 5):
            return []
        autorizados = self._param("CT-DHCP-001", "servidores_autorizados", [])
        if not autorizados:
            if not self._aviso_dhcp:
                log.warning("CT-DHCP-001 sin servidores autorizados configurados: la regla no se evalúa")
                self._aviso_dhcp = True
            return []
        if servidor in autorizados or ts - self._ultimo_dhcp.get(servidor, -1e9) < 60:
            return []
        self._ultimo_dhcp[servidor] = ts
        return [Deteccion("CT-DHCP-001", ts, servidor, mac, {str(pkt[IP].dst)}, {67}, "udp",
                          f"Respuesta DHCP desde {servidor}, que no es un servidor autorizado", [pkt])]
