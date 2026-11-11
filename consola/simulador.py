"""Sensor simulado para el modo demostración.

Genera tráfico de fondo y escenarios de ataque interno (escaneos, movimiento
lateral, fuerza bruta, suplantación) que llegan al Estado como si vinieran del
motor de captura real. No captura ni envía nada a la red.
"""
# Bandit marca random (B311). Es un falso positivo: aquí solo se simula tráfico,
# nunca se usa para claves, tokens ni nonces (eso va con secrets/os.urandom).
import random

from PySide6.QtCore import QObject, QTimer

from consola.estado import Estado

# código de regla: (peso, carga extra en pps)
ESCENARIOS = {
    "CT-SCAN-001": (30, 900),
    "CT-SCAN-002": (18, 500),
    "CT-SCAN-003": (8, 400),
    "CT-LAT-001": (14, 300),
    "CT-AUTH-001": (16, 250),
    "CT-SPOOF-001": (5, 60),
    "CT-DHCP-001": (3, 20),
}
SERVIDORES = [f"10.10.30.{n}" for n in range(11, 31)]


class SensorSimulado(QObject):
    def __init__(self, estado: Estado, intervalo_ms: int = 1000, probabilidad: float = 0.18):
        super().__init__()
        self.estado = estado
        self.probabilidad = probabilidad
        self._en_curso: list[dict] = []
        self._timer = QTimer(self)
        self._timer.setInterval(intervalo_ms)
        self._timer.timeout.connect(self._paso)

    def iniciar(self) -> None:
        self._timer.start()

    def detener(self) -> None:
        self._timer.stop()

    def _paso(self) -> None:
        if random.random() < self.probabilidad and len(self._en_curso) < 3:
            self._en_curso.append(self._nuevo_escenario())
        carga = 0
        for escenario in list(self._en_curso):
            self._emitir(escenario)
            carga += escenario["carga"]
            escenario["pasos"] -= 1
            if escenario["pasos"] <= 0:
                self._en_curso.remove(escenario)
        pps = max(0, int(random.gauss(1800, 140)) + carga)
        self.estado.agregar_metrica(pps, max(0, int((pps - 3200) * 0.04)))
        self.estado.tick()
        self.estado.notificar()

    def _nuevo_escenario(self) -> dict:
        codigos = list(ESCENARIOS)
        codigo = random.choices(codigos, weights=[ESCENARIOS[c][0] for c in codigos])[0]
        if codigo == "CT-LAT-001" and random.random() < 0.15:
            ip = "10.10.30.10"   # el DNS/DC también se mueve "lateralmente": activo protegido
        else:
            ip = f"10.10.20.{random.randint(10, 220)}"
        mac = "02:" + ":".join(f"{random.randint(0, 255):02x}" for _ in range(5))
        return {"codigo": codigo, "ip": ip, "mac": mac, "pasos": random.randint(3, 8),
                "carga": ESCENARIOS[codigo][1], "objetivo": random.choice(SERVIDORES)}

    def _emitir(self, e: dict) -> None:
        codigo, destinos, puertos = e["codigo"], (), ()
        if codigo == "CT-SCAN-001":
            destinos, puertos = (e["objetivo"],), random.sample(range(1, 1025), 25)
        elif codigo == "CT-SCAN-002":
            destinos = [f"10.10.20.{random.randint(2, 254)}" for _ in range(30)]
        elif codigo == "CT-SCAN-003":
            destinos, puertos = (e["objetivo"],), random.sample(range(1, 1025), 8)
        elif codigo == "CT-LAT-001":
            destinos, puertos = random.sample(SERVIDORES, 2), random.sample([445, 3389, 5985, 22], 2)
        elif codigo == "CT-AUTH-001":
            destinos, puertos = (e["objetivo"],), (22,)
        elif codigo == "CT-SPOOF-001":
            destinos = ("10.10.20.1",)
        self.estado.registrar_evento(codigo, e["ip"], e["mac"], destinos, puertos)
