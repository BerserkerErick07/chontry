"""Centro de control: rutas, comandos de los componentes y lectura de configuración."""
import sys
import tempfile
import unittest
from pathlib import Path

from comun.config import leer_env, usar_env
from lanzador import servicios as s


class PruebasLanzador(unittest.TestCase):
    def test_rutas_quedan_en_la_carpeta_del_usuario(self):
        with tempfile.TemporaryDirectory() as tmp:
            r = s.Rutas(Path(tmp))
            self.assertTrue(r.datos.is_dir() and r.pcaps.is_dir())
            self.assertEqual(r.env_lab.parent, Path(tmp))
            self.assertEqual(r.bandera_sensor.parent, r.datos)

    def test_comando_desde_el_codigo_fuente(self):
        linea = s.comando("sensor", "--solo-contencion")
        self.assertEqual(linea[1:], ["-m", "sensor", "--solo-contencion"])
        self.assertTrue(Path(linea[0]).name.lower().startswith("python"))

    def test_leer_env_no_toca_el_entorno(self):
        with tempfile.TemporaryDirectory() as tmp:
            archivo = Path(tmp) / ".env.lab"
            archivo.write_text("# comentario\nA=1\nB='dos'\nmal\n", encoding="utf-8")
            self.assertEqual(leer_env(archivo), {"A": "1", "B": "dos"})

    def test_usar_env_quita_el_parametro(self):
        argumentos = usar_env(["--pcap", "x.pcap", "--env", "C:/datos/.env.lab", "--sin-bd"])
        self.assertEqual(argumentos, ["--pcap", "x.pcap", "--sin-bd"])
        import os
        self.assertEqual(os.environ.pop("CHONTRY_ENV"), "C:/datos/.env.lab")

    @unittest.skipUnless(sys.platform == "win32", "solo Windows")
    def test_detecciones_de_windows_no_fallan(self):
        self.assertIsInstance(s.npcap_instalado(), bool)
        self.assertIsInstance(s.es_administrador(), bool)


if __name__ == "__main__":
    unittest.main()
