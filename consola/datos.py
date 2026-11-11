"""Catálogo local para el modo demostración (copia de los datos semilla de la BD)."""
from comun.reglas_base import CONFIG_BASE, REGLAS_BASE
from consola.estado import Regla

REGLAS_LOCALES = [Regla(**regla) for regla in REGLAS_BASE]
CONFIG_LOCAL = dict(CONFIG_BASE)
