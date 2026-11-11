"""Prueba de punta a punta contra un PostgreSQL REAL (local o el servicio de CI).

Se ejecuta solo si existe CHONTRY_PRUEBAS_PG_ADMIN (superusuario de un PostgreSQL en
localhost). Crea una base `chontry_ci` desde cero con las migraciones, logins por rol y
usuarios con TOTP; corre el sensor sobre ataques reales, opera la consola con cada rol y
al final borra todo.
"""
import os
import time
import unittest

import pyotp

from comun.config import RAIZ, cargar_env
from comun.cripto import Cifrador
from comun.db import conectar

cargar_env(RAIZ / ".env.pruebas")
URL_PG = os.environ.get("CHONTRY_PRUEBAS_PG_ADMIN")


@unittest.skipUnless(URL_PG, "sin PostgreSQL de pruebas (CHONTRY_PRUEBAS_PG_ADMIN)")
class PruebaExtremoAExtremo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from herramientas import laboratorio
        cls.lab = laboratorio
        cls.env = laboratorio.montar(URL_PG, salida=lambda *_: None, bd="chontry_ci", prefijo="ct_ci")
        os.environ["CHONTRY_CLAVE_MAESTRA"] = cls.env["CHONTRY_CLAVE_MAESTRA"]
        cls.cifrador = Cifrador.desde_entorno()
        cls._correr_sensor()
        # Una sola sesión por rol: el TOTP es de un solo uso y no se puede repetir en la misma ventana
        cls.admin = cls._entrar("admin")
        cls.analista = cls._entrar("analista")

    @classmethod
    def tearDownClass(cls):
        cls.admin.cerrar()
        cls.analista.cerrar()
        cls.lab.desmontar(URL_PG, "chontry_ci", "ct_ci")
        os.environ.pop("CHONTRY_CLAVE_MAESTRA", None)

    # -------------------------------------------------------------- ayudas
    @classmethod
    def _servicio_sensor(cls):
        from sensor.servicio import Servicio
        url = cls.env["CHONTRY_DB_URL_SENSOR"]
        return Servicio(lambda: conectar(url), cls.env["CHONTRY_SENSOR_ID"], cls.cifrador)

    @classmethod
    def _correr_sensor(cls, escenarios=None):
        from herramientas import generar_pcaps as g
        servicio = cls._servicio_sensor()
        servicio.publicador.start()
        reloj = g.Reloj(time.time() - 300)
        for escenario in escenarios or g.ESCENARIOS.values():
            for paquete in escenario(reloj):
                servicio.procesar(paquete)
        servicio.motor.tick(float("inf"))
        servicio.detener()
        return servicio

    def _admin_bd(self):
        return conectar(self.env["CHONTRY_DB_URL_ADMIN"], permitir_dueno=True)

    @classmethod
    def _entrar(cls, rol: str):
        from consola.acceso import ServicioAcceso
        from consola.repositorio import EstadoNeon
        prefijo = rol.upper()
        url = cls.env[{"admin": "CHONTRY_DB_URL", "analista": "CHONTRY_DB_URL_ANALISTA",
                       "auditor": "CHONTRY_DB_URL_AUDITOR"}[rol]]
        conexion = conectar(url)
        servicio = ServicioAcceso(conexion, cls.cifrador)
        servicio.verificar_clave(cls.env[f"LAB_{prefijo}_USUARIO"], cls.env[f"LAB_{prefijo}_CLAVE"])
        codigo = pyotp.TOTP(cls.env[f"LAB_{prefijo}_TOTP"]).now()
        servicio.verificar_totp(codigo)
        setattr(cls, f"codigo_{rol}", codigo)
        estado = EstadoNeon(conexion, url, servicio.completar(), servicio.sesion_id, cls.cifrador)
        estado._refrescador.detener()       # en la prueba se refresca a mano
        return estado

    def _refrescar(self, estado):
        from consola.repositorio import _leer_todo
        estado._aplicar(_leer_todo(estado._conexion, estado.sesion_id))

    # -------------------------------------------------------------- pruebas
    def test_1_sensor_escribio_alertas_contenciones_y_evidencias(self):
        with self._admin_bd() as c:
            reglas = {f[0] for f in c.execute("""select r.codigo from chontry.alertas a
                                                 join chontry.reglas_deteccion r on r.id = a.regla_id""")}
            self.assertEqual(reglas, {"CT-SCAN-001", "CT-SCAN-002", "CT-SCAN-003", "CT-LAT-001", "CT-AUTH-001",
                                      "CT-SPOOF-001", "CT-DHCP-001"})
            self.assertGreater(c.execute("select count(*) from chontry.evidencias").fetchone()[0], 0)
            protegido = c.execute("""select count(*) from chontry.contenciones ct join chontry.activos a
                                     on a.id = ct.activo_id where host(a.ip) = '10.10.30.10'""").fetchone()[0]
            self.assertEqual(protegido, 0, "un activo protegido nunca se contiene")
            span = c.execute("select count(*) from chontry.contenciones where puerto_switch = 'Gi1/0/48'").fetchone()[0]
            self.assertEqual(span, 0, "nunca se aísla el puerto SPAN")
            self.assertEqual(c.execute("select count(*) from chontry.verificar_auditoria()").fetchone()[0], 0)

    def test_2_flujo_de_contencion_por_roles(self):
        from comun.validacion import EntradaInvalida
        from consola.estado import PermisoDenegado
        analista, admin = self.analista, self.admin
        # El analista propone; ni la interfaz ni la BD le dejan aprobar
        libre = next(a for a in analista.activos if not a[9] and a[1] and a[1].startswith("10.10.20.1"))
        analista.proponer_manual(libre[1], "Gi1/0/12", 999, "prueba de integración: host sospechoso")
        self._refrescar(analista)
        propuesta = next(c for c in analista.contenciones if c.ip == libre[1] and c.estado == "propuesta")
        with self.assertRaises(PermisoDenegado):
            analista.aprobar(propuesta.id)
        with self.assertRaises(PermisoDenegado):
            analista._ejecutar("update chontry.contenciones set estado = 'aprobada' where id = %s", (propuesta.id,))
        with self.assertRaises(EntradaInvalida):    # puerto SPAN rechazado por la BD
            analista.proponer_manual("10.10.20.11", "Gi1/0/48", 999, "esto apunta al puerto del sensor")
        # El admin aprueba y el sensor ejecuta; luego el admin libera y el sensor revierte
        admin.aprobar(propuesta.id)
        sensor = self._servicio_sensor()
        sensor.publicador.start()
        sensor._atender_contenciones()
        sensor.publicador.detener()
        self._refrescar(admin)
        self.assertEqual(admin.contencion(propuesta.id).estado, "aplicada")
        admin.revertir(propuesta.id)
        sensor = self._servicio_sensor()
        sensor.publicador.start()
        sensor._atender_contenciones()
        sensor.publicador.detener()
        self._refrescar(admin)
        self.assertEqual(admin.contencion(propuesta.id).estado, "revertida")

    def test_3_evidencia_se_descifra_y_verifica(self):
        alerta = next(a for a in self.admin.alertas if a.regla.codigo == "CT-SCAN-001")
        tipo, contenido = self.admin.evidencias(alerta)[0]
        self.assertEqual(tipo, "pcap")
        self.assertEqual(contenido[:4], bytes.fromhex("d4c3b2a1"))   # cabecera pcap

    def test_4_lista_blanca_suprime_alertas(self):
        from herramientas import generar_pcaps as g
        self.admin.agregar_lista_blanca("10.10.20.123", "CT-SCAN-001", "escáner autorizado en la prueba", 1)
        servicio = self._correr_sensor([lambda r: g.escaneo_puertos(r, atacante="10.10.20.123")])
        self.assertGreater(servicio.motor.estadisticas["ignoradas"], 0)
        self.assertEqual(servicio.motor.estadisticas["alertas"], 0)

    def test_5_bloqueo_por_intentos_y_mensaje_generico(self):
        from consola.acceso import AccesoDenegado, ServicioAcceso
        conexion = conectar(self.env["CHONTRY_DB_URL_AUDITOR"])
        try:
            mensajes = set()
            for _ in range(5):
                with self.assertRaises(AccesoDenegado) as ctx:
                    ServicioAcceso(conexion, self.cifrador).verificar_clave(self.env["LAB_AUDITOR_USUARIO"], "clave-errada")
                mensajes.add(str(ctx.exception))
            with self.assertRaises(AccesoDenegado):      # bloqueada: ni la clave correcta entra
                ServicioAcceso(conexion, self.cifrador).verificar_clave(self.env["LAB_AUDITOR_USUARIO"],
                                                                         self.env["LAB_AUDITOR_CLAVE"])
            with self.assertRaises(AccesoDenegado) as ctx:   # usuario inexistente: mismo mensaje
                ServicioAcceso(conexion, self.cifrador).verificar_clave("no.existe", "x")
            mensajes.add(str(ctx.exception))
            self.assertEqual(len(mensajes), 1)
        finally:
            conexion.close()

    def test_6_totp_es_de_un_solo_uso(self):
        from consola.acceso import AccesoDenegado, ServicioAcceso
        # Repetir el mismo código que ya usó el analista al iniciar sesión debe fallar
        conexion = conectar(self.env["CHONTRY_DB_URL_ANALISTA"])
        try:
            servicio = ServicioAcceso(conexion, self.cifrador)
            servicio.verificar_clave(self.env["LAB_ANALISTA_USUARIO"], self.env["LAB_ANALISTA_CLAVE"])
            with self.assertRaises(AccesoDenegado):
                servicio.verificar_totp(self.codigo_analista)
        finally:
            conexion.close()

    def test_8_admin_cierra_sesiones_de_otro_usuario(self):
        from consola.repositorio import _leer_todo
        self.assertTrue(_leer_todo(self.analista._conexion, self.analista.sesion_id)["sesion_valida"])
        self.admin.administrar_usuario(self.analista.usuario_id, "cerrar_sesiones")
        self.assertFalse(_leer_todo(self.analista._conexion, self.analista.sesion_id)["sesion_valida"])

    def test_7_auditor_es_solo_lectura(self):
        from consola.estado import PermisoDenegado
        auditor = None
        try:
            from consola.acceso import ServicioAcceso
            with self._admin_bd() as c:   # desbloquea al auditor (test_5 lo bloqueó)
                c.execute("update chontry.usuarios set intentos_fallidos = 0, bloqueado_hasta = null "
                          "where usuario = %s", (self.env["LAB_AUDITOR_USUARIO"],))
            auditor = self._entrar("auditor")
            self.assertTrue(auditor.alertas)
            with self.assertRaises(PermisoDenegado):
                auditor._ejecutar("update chontry.alertas set estado = 'cerrada' where id = %s", (auditor.alertas[0].id,))
            self.assertEqual(auditor.verificar_auditoria(), [])
        finally:
            if auditor:
                auditor.cerrar()


if __name__ == "__main__":
    unittest.main()
