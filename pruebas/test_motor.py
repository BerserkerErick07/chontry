"""Decisiones del motor del sensor: agregación, lista blanca, protegidos, tope, SPAN y evidencias."""
import os
import time
import unittest

from comun.cripto import Cifrador
from herramientas import generar_pcaps as g
from sensor.catalogo import Catalogo
from sensor.contencion import Ejecutor
from sensor.detector import Detector
from sensor.motor import Motor


class PublicadorFalso:
    def __init__(self):
        self.ops = []

    def enviar(self, operacion, /, **datos):
        self.ops.append((operacion, datos))

    def de(self, tipo):
        return [d for t, d in self.ops if t == tipo]


SWITCH = {"id": 1, "nombre": "sw-lab-01", "ip": "10.10.10.2", "fabricante": "cisco_ios", "credencial_ref": "x",
          "huella": None, "vlan_cuarentena": 999, "puerto_ssh": 22, "habilitado": True, "puerto_span": "Gi1/0/48"}


def armar(**config):
    catalogo = Catalogo()
    catalogo.config.update(config)
    catalogo.switches = {1: dict(SWITCH)}
    catalogo.segmentos = [{"id": 2, "red": "10.10.20.0/24", "vlan": 20, "tipo": "usuarios"},
                          {"id": 3, "red": "10.10.30.0/24", "vlan": 30, "tipo": "servidores"}]
    publicador = PublicadorFalso()
    motor = Motor(catalogo, publicador, Ejecutor("simulado"), Cifrador(os.urandom(32)), "sensor-1")
    detector = Detector(catalogo.reglas_detector())
    return motor, detector, publicador, catalogo


def correr(motor, detector, paquetes):
    for p in paquetes:
        for d in detector.procesar(p):
            motor.manejar(d)
    motor.tick(float("inf"))
    motor.cerrar()


class PruebasMotor(unittest.TestCase):
    def test_agrega_rafagas_en_una_alerta_con_evidencia_cifrada(self):
        motor, detector, pub, _ = armar()
        correr(motor, detector, g.escaneo_puertos(g.Reloj(time.time())))
        self.assertEqual(len(pub.de("alerta_crear")), 1)
        self.assertGreaterEqual(pub.de("alerta_actualizar")[-1]["conteo"], 5)
        evidencia = pub.de("evidencia")[0]
        self.assertEqual(evidencia["tipo"], "pcap")
        self.assertNotIn("10.10.20.66", evidencia["contenido"])      # va cifrada, no en claro

    def test_contener_aplica_y_proponer_queda_pendiente(self):
        motor, detector, pub, _ = armar()
        reloj = g.Reloj(time.time())
        correr(motor, detector, g.escaneo_sigiloso(reloj) + g.fuerza_bruta(reloj))
        estados = {c["mac"]: (c["modo"], c["estado"]) for c in pub.de("contencion_crear")}
        self.assertEqual(estados[g.mac_de("10.10.20.88")], ("automatica", "aplicada"))
        self.assertEqual(estados[g.mac_de("10.10.20.55")], ("manual", "propuesta"))

    def test_activo_protegido_nunca_se_contiene(self):
        motor, detector, pub, catalogo = armar()
        catalogo.protegidos_ip = {"10.10.30.10"}
        correr(motor, detector, g.protegido_lateral(g.Reloj(time.time())))
        self.assertEqual(pub.de("contencion_crear"), [])
        self.assertEqual(pub.de("auditar")[0]["accion"], "contencion_omitida")

    def test_lista_blanca(self):
        motor, detector, pub, catalogo = armar()
        catalogo.lista_blanca = [{"red": "10.10.20.66/32", "mac": None, "regla": "CT-SCAN-001", "expira": None}]
        correr(motor, detector, g.escaneo_puertos(g.Reloj(time.time())))
        self.assertEqual(pub.de("alerta_crear"), [])
        self.assertGreater(motor.estadisticas["ignoradas"], 0)

    def test_tope_por_hora_pasa_a_aprobacion(self):
        motor, detector, pub, _ = armar(**{"contencion.max_por_hora": 1})
        reloj = g.Reloj(time.time())
        correr(motor, detector, g.escaneo_sigiloso(reloj, atacante="10.10.20.81") +
               g.escaneo_sigiloso(reloj, atacante="10.10.20.82"))
        modos = sorted(c["modo"] for c in pub.de("contencion_crear"))
        self.assertEqual(modos, ["automatica", "manual"])

    def test_nunca_aisla_el_puerto_span(self):
        motor, detector, pub, catalogo = armar()
        mac = g.mac_de("10.10.20.88")
        catalogo.activos[mac] = {"ip": "10.10.20.88", "protegido": False, "switch_id": 1, "puerto": "Gi1/0/48",
                                 "vlan": 20}
        correr(motor, detector, g.escaneo_sigiloso(g.Reloj(time.time())))
        self.assertEqual(pub.de("contencion_crear"), [])
        self.assertIn("SPAN", pub.de("auditar")[0]["detalle"]["motivo"])

    def test_sin_switch_no_contiene_y_lo_audita(self):
        motor, detector, pub, catalogo = armar()
        catalogo.switches = {}
        correr(motor, detector, g.escaneo_sigiloso(g.Reloj(time.time())))
        self.assertEqual(pub.de("contencion_crear"), [])
        self.assertEqual(pub.de("auditar")[0]["accion"], "contencion_imposible")


class PruebasEjecutor(unittest.TestCase):
    def test_simulado_usa_plantilla_y_no_conecta(self):
        ok, salida = Ejecutor("simulado").aplicar(SWITCH, "Gi1/0/5", 999)
        self.assertTrue(ok)
        self.assertIn("SIMULADO", salida)
        self.assertIn("switchport access vlan 999", salida)

    def test_real_sin_huella_no_envia_credenciales(self):
        ok, salida = Ejecutor("real").aplicar({**SWITCH, "ip": "127.0.0.1"}, "Gi1/0/5", 999)
        self.assertFalse(ok)
        self.assertIn("huella", salida.lower())


if __name__ == "__main__":
    unittest.main()
