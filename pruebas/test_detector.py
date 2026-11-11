"""Cada regla detecta su ataque y el tráfico normal no genera alertas (falsos positivos)."""
import time
import unittest

from comun.reglas_base import REGLAS_BASE
from herramientas import generar_pcaps as g
from sensor.detector import Detector


def _detector():
    return Detector({r["codigo"]: {"habilitada": True, "parametros": r["parametros"]} for r in REGLAS_BASE})


def _correr(paquetes, detector=None):
    detector = detector or _detector()
    return [d for p in paquetes for d in detector.procesar(p)]


class PruebasReglas(unittest.TestCase):
    def setUp(self):
        self.reloj = g.Reloj(time.time())

    def test_trafico_normal_no_genera_alertas(self):
        self.assertEqual(_correr(g.trafico_normal(self.reloj, 300)), [])

    def test_cada_ataque_dispara_su_regla(self):
        casos = {
            "CT-SCAN-001": (g.escaneo_puertos, "10.10.20.66"),
            "CT-SCAN-002": (g.barrido_hosts, "10.10.20.77"),
            "CT-SCAN-003": (g.escaneo_sigiloso, "10.10.20.88"),
            "CT-LAT-001": (g.movimiento_lateral, "10.10.20.99"),
            "CT-AUTH-001": (g.fuerza_bruta, "10.10.20.55"),
            "CT-SPOOF-001": (g.arp_spoofing, "10.10.20.44"),
            "CT-DHCP-001": (g.dhcp_falso, "10.10.20.250"),
        }
        for codigo, (escenario, origen) in casos.items():
            with self.subTest(regla=codigo):
                detecciones = _correr(escenario(self.reloj))
                self.assertTrue(detecciones, f"{codigo} no se detectó")
                self.assertTrue(all(d.codigo == codigo for d in detecciones))
                self.assertEqual(detecciones[0].ip_origen, origen)
                self.assertTrue(detecciones[0].paquetes, "la detección debe traer paquetes de evidencia")

    def test_arp_spoofing_culpa_al_atacante_no_al_gateway(self):
        d = _correr(g.arp_spoofing(self.reloj))[0]
        self.assertEqual(d.mac_origen, g.mac_de("10.10.20.44"))
        self.assertEqual(d.destinos, {g.GATEWAY})

    def test_dhcp_autorizado_no_alerta(self):
        detecciones = _correr(g.dhcp_falso(self.reloj))
        self.assertEqual({d.ip_origen for d in detecciones}, {"10.10.20.250"})

    def test_regla_deshabilitada_no_alerta(self):
        detector = _detector()
        detector.reglas["CT-SCAN-001"]["habilitada"] = False
        self.assertEqual(_correr(g.escaneo_puertos(self.reloj), detector), [])

    def test_umbral_configurable(self):
        detector = _detector()
        detector.reglas["CT-SCAN-001"]["parametros"] = {"puertos_distintos": 150, "ventana_seg": 10}
        self.assertEqual(_correr(g.escaneo_puertos(self.reloj), detector), [])

    def test_escaneo_lento_fuera_de_ventana_no_alerta(self):
        lento = g.escaneo_puertos(g.Reloj(time.time()))
        for i, paquete in enumerate(lento):
            paquete.time = time.time() + i * 2.0     # un SYN cada 2 s: nunca 20 puertos en 10 s
        self.assertEqual(_correr(lento), [])


if __name__ == "__main__":
    unittest.main()
