"""Pruebas de los controles de la Clase 3 en comun/.  Ejecutar:  python -m unittest -v"""
import logging
import unittest

from comun import db, errores, validacion
from comun.validacion import EntradaInvalida


class PruebasValidacion(unittest.TestCase):
    def test_ip_valida_e_invalida(self):
        self.assertEqual(str(validacion.validar_ip("10.10.20.5")), "10.10.20.5")
        for mala in ("10.10.20.300", "10.10.20.5; reboot", "", "1" * 50):
            with self.assertRaises(EntradaInvalida):
                validacion.validar_ip(mala)

    def test_puerto_y_vlan_en_rango(self):
        self.assertEqual(validacion.validar_puerto("443"), 443)
        self.assertEqual(validacion.validar_vlan(999), 999)
        for malo in (0, 65536, "-1", "22 ", "２２", True):
            with self.assertRaises(EntradaInvalida):
                validacion.validar_puerto(malo)
        with self.assertRaises(EntradaInvalida):
            validacion.validar_vlan(4095)

    def test_interfaz_rechaza_inyeccion(self):
        for buena in ("Gi1/0/1", "GigabitEthernet1/0/24", "Te1/1/1.100", "A1", "24"):
            self.assertEqual(validacion.validar_interfaz_switch(buena), buena)
        for mala in ("Gi1/0/1\nreload", "Gi1/0/1\n", "Gi1/0/1 ; reload", "Gi1/0/1|x", ""):
            with self.assertRaises(EntradaInvalida):
                validacion.validar_interfaz_switch(mala)

    def test_filtro_bpf(self):
        self.assertTrue(validacion.validar_filtro_bpf("not port 22 and (tcp or udp)"))
        for malo in ("tcp; rm -rf /", "tcp && reboot", "tcp`id`", "tcp\nudp"):
            with self.assertRaises(EntradaInvalida):
                validacion.validar_filtro_bpf(malo)

    def test_plantilla_de_cuarentena(self):
        self.assertEqual(validacion.comandos_cuarentena("cisco_ios", "Gi1/0/5", 999),
                         ["interface Gi1/0/5", "switchport access vlan 999"])
        with self.assertRaises(EntradaInvalida):
            validacion.comandos_cuarentena("cisco_ios", "Gi1/0/5\nreload", 999)
        with self.assertRaises(EntradaInvalida):
            validacion.comandos_cuarentena("vendedor_x", "Gi1/0/5", 999)


class PruebasErrores(unittest.TestCase):
    def test_limpia_secretos_y_correos(self):
        texto = ("postgresql://ct_erick:npg_ABC123@host/db password=hunter2 "  # secreto-ficticio
                 "token: abcd $argon2id$v=19$m=65536$sal$hash correo erick@ejemplo.com")
        limpio = errores.limpiar(texto)
        for secreto in ("npg_ABC123", "hunter2", "abcd", "$sal$hash", "erick@ejemplo.com"):
            self.assertNotIn(secreto, limpio)

    def test_mensaje_generico_y_detalle_al_log(self):
        with self.assertLogs("chontry", level=logging.ERROR) as log:
            mensaje = errores.manejar_error(RuntimeError("tabla chontry.auditoria"), "prueba")
        self.assertNotIn("auditoria", mensaje)
        self.assertIn("Contacte al administrador", mensaje)
        self.assertIn("auditoria", "\n".join(log.output))


class PruebasConexion(unittest.TestCase):
    URL = "postgresql://ct_erick:x@host/neondb"  # secreto-ficticio

    def test_exige_verify_full_y_channel_binding(self):
        for consulta in ("", "?sslmode=require&channel_binding=require", "?sslmode=verify-full"):
            with self.assertRaises(db.ConfiguracionInsegura):
                db.url_segura(self.URL + consulta)

    def test_rechaza_rol_dueno(self):
        with self.assertRaises(db.ConfiguracionInsegura):
            db.url_segura("postgresql://neondb_owner:x@host/neondb?sslmode=verify-full&channel_binding=require")  # secreto-ficticio

    def test_url_valida_agrega_ca(self):
        url = db.url_segura(self.URL + "?sslmode=verify-full&channel_binding=require")
        self.assertIn("sslrootcert=", url)

    def test_ruta_con_espacios_se_codifica_para_libpq(self):
        # libpq no entiende "+" como espacio: las rutas con espacios deben ir como %20
        url = db.url_segura(self.URL + "?sslmode=verify-full&channel_binding=require&sslrootcert=C:/Mis Datos/ca.pem")
        self.assertIn("sslrootcert=C%3A%2FMis%20Datos%2Fca.pem", url)
        self.assertNotIn("+", url)

    def test_error_no_revela_la_url(self):
        with self.assertRaises(db.ConfiguracionInsegura) as ctx:
            db.url_segura("postgresql://ct_erick:secreto123@host/neondb?sslmode=require")  # secreto-ficticio
        self.assertNotIn("secreto123", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
