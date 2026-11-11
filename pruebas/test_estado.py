"""Pruebas de las reglas de seguridad del Estado de la consola.  python -m unittest -v"""
import unittest

from comun.validacion import EntradaInvalida
from consola.datos import CONFIG_LOCAL, REGLAS_LOCALES
from consola.estado import Estado, PermisoDenegado


def nuevo_estado(rol="admin", **config):
    return Estado("prueba", rol, REGLAS_LOCALES, {**CONFIG_LOCAL, **config}, "Local")


class PruebasDeteccion(unittest.TestCase):
    def test_agrega_eventos_del_mismo_origen_y_regla(self):
        estado = nuevo_estado()
        a1 = estado.registrar_evento("CT-SCAN-001", "10.10.20.50", "02:00:00:00:00:01", ["10.10.30.11"], [22, 80])
        a2 = estado.registrar_evento("CT-SCAN-001", "10.10.20.50", "02:00:00:00:00:01", ["10.10.30.11"], [443])
        self.assertIs(a1, a2)
        self.assertEqual(a1.conteo, 2)
        self.assertEqual(a1.puertos, {22, 80, 443})

    def test_regla_contener_aisla_automaticamente(self):
        estado = nuevo_estado()
        alerta = estado.registrar_evento("CT-SPOOF-001", "10.10.20.66", "02:00:00:00:00:02", ["10.10.20.1"])
        contencion = estado.contenciones[-1]
        self.assertEqual((contencion.modo, contencion.estado), ("automatica", "aplicada"))
        self.assertEqual(alerta.estado, "contenida")
        self.assertEqual(contencion.comandos, ["interface Gi1/0/19", "switchport access vlan 999"])

    def test_regla_proponer_queda_pendiente(self):
        estado = nuevo_estado()
        estado.registrar_evento("CT-SCAN-001", "10.10.20.70", "02:00:00:00:00:03")
        self.assertEqual(estado.contenciones[-1].estado, "propuesta")

    def test_activo_protegido_nunca_se_contiene(self):
        estado = nuevo_estado()
        estado.registrar_evento("CT-LAT-001", "10.10.30.10", "02:00:00:00:00:04", ["10.10.30.11"], [445])
        self.assertEqual(estado.contenciones, [])
        self.assertEqual(estado.auditoria[-1].accion, "contencion_omitida")

    def test_tope_de_contenciones_automaticas(self):
        estado = nuevo_estado(**{"contencion.max_por_hora": 2})
        for n in range(4):
            estado.registrar_evento("CT-SPOOF-001", f"10.10.20.{100 + n}", "02:00:00:00:00:05")
        modos = [c.modo for c in estado.contenciones]
        self.assertEqual(modos, ["automatica", "automatica", "manual", "manual"])
        self.assertEqual(estado.contenciones[-1].estado, "propuesta")


class PruebasAutorizacion(unittest.TestCase):
    def test_analista_no_aprueba_ni_revierte(self):
        estado = nuevo_estado("analista")
        estado.registrar_evento("CT-SCAN-001", "10.10.20.80", "02:00:00:00:00:06")
        cid = estado.contenciones[-1].id
        for accion in (estado.aprobar, estado.rechazar, estado.revertir):
            with self.assertRaises(PermisoDenegado):
                accion(cid)
        self.assertEqual(estado.contenciones[-1].estado, "propuesta")
        self.assertEqual(estado.auditoria[-1].accion, "acceso_denegado")

    def test_admin_aprueba_y_revierte(self):
        estado = nuevo_estado("admin")
        alerta = estado.registrar_evento("CT-SCAN-001", "10.10.20.81", "02:00:00:00:00:07")
        cid = estado.contenciones[-1].id
        estado.aprobar(cid)
        self.assertEqual(estado.contencion(cid).estado, "aplicada")
        self.assertEqual(alerta.estado, "contenida")
        estado.revertir(cid)
        self.assertEqual(estado.contencion(cid).estado, "revertida")
        self.assertEqual(alerta.estado, "en_revision")


class PruebasContencionManual(unittest.TestCase):
    def test_rechaza_entradas_maliciosas_o_peligrosas(self):
        estado = nuevo_estado("analista")
        casos = [
            ("10.10.20.300", "Gi1/0/5", 999, "motivo suficiente"),       # IP inválida
            ("10.10.20.5", "Gi1/0/5\nreload", 999, "motivo suficiente"),  # inyección en el puerto
            ("10.10.20.5", "Gi1/0/5", 5000, "motivo suficiente"),         # VLAN fuera de rango
            ("10.10.20.5", "Gi1/0/5", 20, "motivo suficiente"),           # misma VLAN de origen
            ("10.10.20.5", "Gi1/0/5", 999, "corto"),                      # motivo muy corto
            ("10.10.20.1", "Gi1/0/1", 999, "aislar el gateway"),          # activo protegido
        ]
        for ip, puerto, vlan, motivo in casos:
            with self.subTest(ip=ip, puerto=puerto, vlan=vlan):
                with self.assertRaises(EntradaInvalida):
                    estado.proponer_manual(ip, puerto, vlan, motivo)
        self.assertEqual(estado.contenciones, [])

    def test_propuesta_valida(self):
        estado = nuevo_estado("analista")
        c = estado.proponer_manual("10.10.20.45", "Gi1/0/12", 999, "reportado por el área de TI")
        self.assertEqual((c.estado, c.solicitado_por), ("propuesta", "prueba"))


class PruebasAuditoria(unittest.TestCase):
    def test_cadena_integra_y_deteccion_de_manipulacion(self):
        estado = nuevo_estado()
        for n in range(5):
            estado.registrar_evento("CT-SCAN-002", f"10.10.20.{20 + n}", "02:00:00:00:00:08")
        self.assertEqual(estado.verificar_auditoria(), [])
        alterado = estado.alterar_registro_demo()
        self.assertEqual(estado.verificar_auditoria(), [alterado])

    def test_borrar_un_registro_rompe_la_cadena(self):
        estado = nuevo_estado()
        for n in range(4):
            estado.registrar_evento("CT-SCAN-002", f"10.10.20.{40 + n}", "02:00:00:00:00:09")
        borrado = estado.auditoria.pop(2)
        self.assertEqual(estado.verificar_auditoria(), [borrado.id + 1])


if __name__ == "__main__":
    unittest.main()
