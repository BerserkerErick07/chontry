"""Contraseñas Argon2id, política de claves, AES-256-GCM y TOTP de un solo uso."""
import os
import time
import unittest

import pyotp
from cryptography.exceptions import InvalidTag

from comun import cripto
from comun.validacion import EntradaInvalida


class PruebasClaves(unittest.TestCase):
    def test_argon2id(self):
        h = cripto.hashear_clave("una frase larga y segura")
        self.assertTrue(h.startswith("$argon2id$"))
        self.assertTrue(cripto.verificar_clave(h, "una frase larga y segura"))
        self.assertFalse(cripto.verificar_clave(h, "otra"))
        self.assertFalse(cripto.verificar_clave(None, "lo que sea"))
        self.assertFalse(cripto.verificar_clave("no-es-un-hash", "x"))

    def test_politica(self):
        self.assertEqual(cripto.validar_clave_nueva("caballo bateria grapa", "erick"), "caballo bateria grapa")
        for mala in ("corta", "erick-es-mi-usuario", "123456789012", "aaaaaaaaaaaaaaa", "x" * 129):
            with self.subTest(clave=mala), self.assertRaises(EntradaInvalida):
                cripto.validar_clave_nueva(mala, "erick")


class PruebasCifrado(unittest.TestCase):
    def setUp(self):
        self.cifrador = cripto.Cifrador(os.urandom(32))

    def test_ida_y_vuelta_con_aad(self):
        nonce, c = self.cifrador.cifrar("evidencias", b"pcap", b"uid-1")
        self.assertEqual(len(nonce), 12)
        self.assertEqual(self.cifrador.descifrar("evidencias", nonce, c, b"uid-1"), b"pcap")

    def test_detecta_alteracion_y_contexto(self):
        nonce, c = self.cifrador.cifrar("evidencias", b"pcap", b"uid-1")
        with self.assertRaises(InvalidTag):
            self.cifrador.descifrar("evidencias", nonce, c[:-1] + bytes([c[-1] ^ 1]), b"uid-1")
        with self.assertRaises(InvalidTag):
            self.cifrador.descifrar("evidencias", nonce, c, b"uid-2")      # otra alerta
        with self.assertRaises(InvalidTag):
            self.cifrador.descifrar("mfa", nonce, c, b"uid-1")             # otra subclave

    def test_otra_clave_no_descifra(self):
        blob = self.cifrador.cifrar_texto("mfa", "SECRETO")
        with self.assertRaises(InvalidTag):
            cripto.Cifrador(os.urandom(32)).descifrar_texto("mfa", blob)

    def test_clave_maestra_desde_entorno(self):
        os.environ[cripto.ENV_CLAVE_MAESTRA] = cripto.generar_clave_maestra()
        try:
            self.assertEqual(len(cripto.cargar_clave_maestra()), 32)
            os.environ[cripto.ENV_CLAVE_MAESTRA] = "corta"
            with self.assertRaises(cripto.ClaveNoDisponible):
                cripto.cargar_clave_maestra()
        finally:
            del os.environ[cripto.ENV_CLAVE_MAESTRA]


class PruebasTotp(unittest.TestCase):
    def test_codigo_actual_y_vecinos(self):
        secreto = cripto.generar_secreto_totp()
        totp = pyotp.TOTP(secreto)
        ahora = time.time()
        paso = cripto.paso_totp(secreto, totp.at(ahora), ahora)
        self.assertIsNotNone(paso)
        self.assertEqual(cripto.paso_totp(secreto, totp.at(ahora - 30), ahora), paso - 1)
        self.assertIsNone(cripto.paso_totp(secreto, totp.at(ahora - 120), ahora))

    def test_formato(self):
        secreto = cripto.generar_secreto_totp()
        for malo in ("", "12345", "1234567", "abcdef", "１２３４５６"):
            self.assertIsNone(cripto.paso_totp(secreto, malo))


if __name__ == "__main__":
    unittest.main()
