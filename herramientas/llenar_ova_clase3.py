"""Llena el OVA de la Clase 3 y genera el informe con la función del propio OVA.

Carga CLASE 3.html en el motor web de Qt, pone los hallazgos, los campos y las
fotos en el formulario y llama a generarInformeHTML(): el resultado es el mismo
archivo que produce el botón «Descargar informe Clase 3».

    python herramientas/llenar_ova_clase3.py "RUTA\\CLASE 3.html" "RUTA\\Informe_Clase3_Codificacion_Segura.html"
"""
import base64
import json
import sys
from pathlib import Path

from PySide6.QtCore import QUrl
from PySide6.QtWebEngineCore import QWebEnginePage
from PySide6.QtWidgets import QApplication

RAIZ = Path(__file__).resolve().parent.parent
CAP = RAIZ / "capturas"

INVESTIGACION = [
    {
        "control": "Validación positiva de entradas (lista blanca)",
        "norma": "OWASP ASVS V5 – 5.5 (validación en el servidor) y 5.3 (rechazo de entradas inválidas)",
        "ubicacion": "comun/validacion.py L15-18, L37-65 · consola/ventana.py L13 · db/001_esquema_inicial.sql L50, L87, L99",
        "hallazgo": "Implementado en dos capas. La aplicación valida IP con el módulo ipaddress (no con regex), "
                    "puerto 1-65535, VLAN 1-4094, interfaz y usuario con fullmatch. Encontramos que match() con $ "
                    "acepta un salto de línea final en Python, por eso usamos fullmatch. La base de datos repite la "
                    "regla con CHECK y tipos inet/cidr/macaddr como última línea de defensa. En la consola, el campo "
                    "inválido se marca en rojo y se rechaza (foto 2). Verificado con pruebas unitarias.",
    },
    {
        "control": "Prevención de inyección de comandos en el switch",
        "norma": "OWASP ASVS V5 – 5.3 · NIST SSDF PW.7",
        "ubicacion": "db/002_correcciones_clase3.sql L19-52 · comun/validacion.py L26-30, L88-94",
        "hallazgo": "FALLO ENCONTRADO Y CORREGIDO. Los campos puerto_switch, interfaz_captura y filtro_bpf eran "
                    "texto libre que termina en la CLI del switch o en el filtro de captura; un valor como "
                    "\"Gi1/0/1⏎reload\" habría ejecutado otro comando. Corrección: lista blanca en la BD y en la app, "
                    "fabricantes limitados y comandos generados con plantilla fija (nunca se concatena texto). "
                    "Probado en Neon: se bloquean \"⏎reload\", \"; reload\", \"tcp; rm -rf /\" y \"eth0 && reboot\" (foto 5).",
    },
    {
        "control": "Mensajes de error genéricos (no exponer trazas)",
        "norma": "OWASP ASVS V7 – 7.4.1",
        "ubicacion": "consola/widgets.py L16-30 (accion_segura) · comun/errores.py L15-18, L54-58",
        "hallazgo": "FALLO ENCONTRADO Y CORREGIDO. Los errores de PostgreSQL revelan nombres de esquema y tabla. "
                    "Ahora toda acción de la interfaz pasa por accion_segura: el usuario ve \"Ocurrió un error. "
                    "Contacte al administrador. Código: xxxx\" y el detalle técnico va solo al log interno con ese "
                    "código para correlacionar. En el login se usa siempre \"Credenciales inválidas.\" para no "
                    "revelar si el usuario existe (evita enumeración).",
    },
    {
        "control": "Logging sin credenciales ni datos personales",
        "norma": "OWASP ASVS V7 – 7.1.1 · NIST SSDF PW.9",
        "ubicacion": "comun/errores.py L20-40 · db/002_correcciones_clase3.sql L64, L78",
        "hallazgo": "FALLO ENCONTRADO Y CORREGIDO. La auditoría de la BD copiaba el email del usuario. Ahora excluye "
                    "password_hash, secreto MFA, email y token. El log de la app pasa por un formateador que "
                    "reemplaza contraseñas, cadenas de conexión, hashes Argon2 y correos por ***, incluso dentro de "
                    "trazas de pila. Además el actor de la auditoría es el login real de PostgreSQL (session_user), "
                    "que el cliente no puede falsificar. Verificado en Neon y con prueba unitaria.",
    },
    {
        "control": "Auditoría append-only con integridad verificable",
        "norma": "OWASP ASVS V7 (registro de auditoría) · NIST SSDF PW.9",
        "ubicacion": "db/001_esquema_inicial.sql L291-365 · consola/estado.py L111-117, L329-336",
        "hallazgo": "Implementado. En la BD, triggers rechazan UPDATE, DELETE y TRUNCATE sobre la auditoría "
                    "(probado en Neon) y cada registro guarda el SHA-256 del anterior; verificar_auditoria() da 0 "
                    "fallos. La consola aplica la misma cadena: el botón «Verificar integridad» detecta tanto un "
                    "registro modificado como uno borrado (foto 10). Límite conocido: el dueño de la BD podría "
                    "desactivar triggers, por eso la app nunca usa ese rol.",
    },
    {
        "control": "Hash de contraseñas y cifrado en reposo",
        "norma": "OWASP ASVS V6 (criptografía almacenada)",
        "ubicacion": "db/001_esquema_inicial.sql L53, L212-215",
        "hallazgo": "Implementado en la BD: solo acepta hashes $argon2id$ (rechaza texto plano, MD5 y SHA-1) y las "
                    "evidencias exigen nonce de 12 bytes para AES-256-GCM y su SHA-256 como cadena de custodia. "
                    "SHA-256 se usa solo para integridad, nunca para contraseñas. FALTA: el módulo Python que "
                    "genere los hashes Argon2id (argon2-cffi ya está instalado) y que cifre las evidencias.",
    },
    {
        "control": "TLS con validación del certificado",
        "norma": "OWASP ASVS V9 (comunicaciones)",
        "ubicacion": "comun/db.py L16, L23-41",
        "hallazgo": "FALLO ENCONTRADO Y CORREGIDO. Usábamos sslmode=require, que cifra pero NO valida el "
                    "certificado: es el equivalente en PostgreSQL de verify=False. Ahora se exige "
                    "sslmode=verify-full y channel_binding=require, y se rechaza el rol dueño de la BD. Al probar "
                    "descubrimos que la libpq de Windows no soporta sslrootcert=system; usamos la CA de certifi. "
                    "Verificado contra Neon: conecta, y rechaza un host que no coincide con el certificado.",
    },
    {
        "control": "Autorización por rol (mínimo privilegio)",
        "norma": "OWASP ASVS V4 (control de acceso) · NIST SSDF PW.9",
        "ubicacion": "db/002_correcciones_clase3.sql L98-160, L209-245 · consola/estado.py L158-163",
        "hallazgo": "FALLO ENCONTRADO Y CORREGIDO. El rol de BD de la consola podía cambiar la columna rol "
                    "(escalada a admin). Como la consola es de escritorio, para ella «el servidor» es PostgreSQL: "
                    "ahora hay un login de BD por persona, rol chontry_admin, RLS en usuarios y sesiones, y solo "
                    "un admin aprueba contenciones. En la interfaz los botones se deshabilitan (foto 9), pero el "
                    "control real está en Estado y en la BD. 13 pruebas de autorización OK en Neon.",
    },
]

CAMPOS = {
    "herramientaSast": "Bandit (Python)",
    "totalHallazgos": "8",
    "hallazgosSast": (
        "Bandit 1.7.10 sobre comun/ y consola/ (1.493 líneas de Python): 8 hallazgos, todos de severidad Low "
        "y confianza High. 0 Medium, 0 High (foto 11).\n"
        "Los 8 son B311 (uso de random) en consola/simulador.py. Los interpretamos como FALSO POSITIVO con los "
        "criterios de la guía: el dato no viene de un usuario no confiable y el sink no es criptográfico, porque "
        "random solo genera el tráfico simulado de la demostración. Claves, tokens y nonces se generan con "
        "secrets/os.urandom. No usamos # nosec, para que el criterio quede visible en el reporte.\n"
        "Bandit no analiza SQL, así que lo complementamos con una revisión estática manual del esquema de la BD: "
        "6 fallos (inyección de comandos en campos que llegan al switch, email en la auditoría, errores que "
        "revelan la estructura, TLS sin validar el certificado, escalada de rol y una credencial expuesta fuera "
        "del repositorio). Los 5 de código se corrigieron con las migraciones 002-004 y los módulos de comun/, y "
        "se verificaron con 22 pruebas contra Neon (foto 5) y 22 pruebas unitarias (foto 13). Las propias pruebas "
        "encontraron 2 errores nuestros que también corregimos: una regex con repetición {1,512} (PostgreSQL "
        "admite máximo 255) y un permiso EXECUTE que faltaba."
    ),
    "revisionSecretos": "Sí, no encontramos secretos",
    "detalleSecretos": (
        "Ejecutamos herramientas/buscar_secretos.py sobre todo el proyecto, excluyendo .venv: busca contraseñas "
        "de Neon (npg_), URLs de BD con contraseña, asignaciones password/secret/token/api_key, claves de AWS, "
        "tokens de GitHub y llaves privadas. Resultado: 0 secretos reales (foto 12). Aparecieron 4 coincidencias "
        "en pruebas/test_comun.py; las revisamos una a una: son credenciales ficticias de las pruebas "
        "(\"x\", \"secreto123\") y quedaron marcadas como # secreto-ficticio, igual que un allowlist de gitleaks.\n"
        ".env está en .gitignore y solo existe .env.example sin secretos. La cadena de conexión vive en la "
        "variable de entorno CHONTRY_DB_URL y las credenciales de los switches en el keyring del sistema "
        "operativo. La contraseña de la BD sí se compartió una vez fuera del repositorio (en un chat): la "
        "tratamos como comprometida y se rota antes de la Clase 4. Gitleaks y Bandit quedan configurados en "
        ".pre-commit-config.yaml."
    ),
    "conclusionInvestigacion": (
        "Implementados y verificados: validación positiva en la app y en la BD; prevención de inyección de "
        "comandos con plantillas; mensajes de error genéricos con código de incidente; logs sin credenciales ni "
        "correos; auditoría append-only con cadena SHA-256 verificable; TLS verify-full; autorización por rol "
        "aplicada por PostgreSQL (RLS y roles); obligación de Argon2id para contraseñas; secretos fuera del "
        "repositorio.\n"
        "Encontramos 6 fallos con la revisión y Bandit no reportó nada de severidad media o alta. Corregimos 5 en "
        "la misma clase. Además construimos la consola de escritorio (PySide6), que ya aplica estos controles "
        "en modo demostración con un sensor simulado.\n"
        "Faltan: generar los hashes Argon2id y el TOTP en el login real, cifrar las evidencias con AES-256-GCM, "
        "guardar alertas y contenciones en la BD (hoy están en memoria) y rotar la credencial expuesta."
    ),
    "correcciones": (
        "1. Rotar la contraseña del rol dueño de la BD y crear un login de BD por integrante.\n"
        "2. Login real de la consola: Argon2id (argon2-cffi) + TOTP usando mis_credenciales() y "
        "registrar_login(), y probar ambas funciones con los logins reales.\n"
        "3. Módulo comun/cripto.py: AES-256-GCM para las evidencias del sensor.\n"
        "4. Persistir alertas, contenciones y auditoría de la consola en PostgreSQL.\n"
        "5. Instalar git, activar pre-commit (gitleaks + bandit) y fijar las dependencias con hashes "
        "(pip-compile --generate-hashes)."
    ),
    "fuentesConsultadas": (
        "OWASP ASVS (V4, V5, V6, V7, V9) · OWASP Password Storage Cheat Sheet · OWASP Logging Cheat Sheet · "
        "NIST SP 800-218 SSDF (PW.7, PW.9, PS.1) · ISO/IEC 27033-2 · Documentación de PostgreSQL 18 (CHECK, "
        "triggers, row level security, sslmode, tipos de red) · Documentación de Neon (roles y conexiones "
        "seguras) · Documentación de psycopg 3, Bandit 1.7 y Gitleaks · Documentación de Python (ipaddress, re)."
    ),
}

# (archivo de origen, nombre que aparece en el informe, descripción)
FOTOS = [
    ("admin/01_panel.png", "01_consola_panel.png",
     "Consola de escritorio ChonTry (PySide6) funcionando con el sensor simulado: alertas por severidad, cuarentena y tráfico del SPAN."),
    ("admin/07_validacion_contencion.png", "02_validacion_en_vivo.png",
     "Validación positiva en la interfaz: la IP 10.10.20.999 y el puerto \"Gi1/0/1; reload\" se marcan en rojo y la propuesta se rechaza."),
    ("evidencia/codigo_validacion.png", "03_codigo_validacion.png",
     "comun/validacion.py: listas blancas con fullmatch y plantillas fijas de comandos para el switch."),
    ("evidencia/codigo_sql_inyeccion.png", "04_codigo_sql_inyeccion.png",
     "db/002_correcciones_clase3.sql L19-52: CHECK de lista blanca contra inyección de comandos en la BD."),
    ("evidencia/pruebas_neon.png", "05_pruebas_neon.png",
     "Resultado de las 22 pruebas contra Neon: inyección bloqueada, email fuera de la auditoría y escalada de rol denegada."),
    ("evidencia/codigo_errores_log.png", "06_codigo_errores_log.png",
     "comun/errores.py: mensaje genérico con código de incidente y limpieza de secretos y correos en el log."),
    ("evidencia/codigo_tls.png", "07_codigo_tls.png",
     "comun/db.py: se exige sslmode=verify-full y channel_binding=require, con la CA de certifi."),
    ("evidencia/codigo_sql_autorizacion.png", "08_codigo_sql_autorizacion.png",
     "db/002_correcciones_clase3.sql L118-160: permisos por columna y row level security en usuarios y sesiones."),
    ("analista/03_cuarentena.png", "09_cuarentena_vista_analista.png",
     "Vista del analista: aprobar, rechazar y liberar están deshabilitados (además, la lógica y la BD lo verifican)."),
    ("admin/06_auditoria_manipulada.png", "10_auditoria_manipulacion_detectada.png",
     "Auditoría: se altera un registro y «Verificar integridad» detecta la ruptura de la cadena SHA-256."),
    ("evidencia/sast_bandit.png", "11_sast_bandit.png",
     "Reporte de Bandit: 8 hallazgos Low (B311, falso positivo en el simulador), 0 Medium, 0 High."),
    ("evidencia/revision_secretos.png", "12_revision_secretos.png",
     "Búsqueda de secretos: 0 secretos reales; 4 credenciales ficticias de prueba revisadas y marcadas; .env en .gitignore."),
    ("evidencia/pruebas_unitarias.png", "13_pruebas_unitarias.png",
     "22 pruebas unitarias OK: validación, errores, TLS, autorización, activos protegidos y cadena de auditoría."),
]


def datos() -> dict:
    fotos = []
    for origen, nombre, _ in FOTOS:
        contenido = (CAP / origen).read_bytes()
        if len(contenido) > 5 * 1024 * 1024:
            raise SystemExit(f"{origen} supera los 5 MB que admite el OVA")
        fotos.append({"data": "data:image/png;base64," + base64.b64encode(contenido).decode(), "nombre": nombre})
    descripcion = "\n".join(f"Foto {i}: {desc}" for i, (_, _, desc) in enumerate(FOTOS, 1))
    return {"investigacion": INVESTIGACION, "fotos": fotos, "campos": {**CAMPOS, "descripcionFotos": descripcion}}


SCRIPT = """
(() => {
  const d = %s;
  estado.investigacion.splice(0, estado.investigacion.length, ...d.investigacion);
  estado.fotos.splice(0, estado.fotos.length, ...d.fotos);
  for (const [id, valor] of Object.entries(d.campos)) document.getElementById(id).value = valor;
  renderInvestigacion(); renderFotos(); updateProgress();
  return JSON.stringify({progreso: document.getElementById('progressPct').textContent,
                         campos: document.getElementById('progressSub').textContent,
                         html: generarInformeHTML()});
})()
"""


def main() -> int:
    ova, salida = Path(sys.argv[1]), Path(sys.argv[2])
    app = QApplication(sys.argv)
    pagina = QWebEnginePage()
    resultado = {}

    def al_terminar(valor):
        resultado.update(json.loads(valor) if valor else {"error": "el OVA no devolvió nada"})
        app.quit()

    def al_cargar(ok):
        if not ok:
            resultado["error"] = "no se pudo cargar el OVA"
            app.quit()
            return
        pagina.runJavaScript(SCRIPT % json.dumps(datos(), ensure_ascii=False), 0, al_terminar)

    pagina.loadFinished.connect(al_cargar)
    pagina.load(QUrl.fromLocalFile(str(ova.resolve())))
    app.exec()

    if "error" in resultado:
        print("ERROR:", resultado["error"])
        return 1
    salida.write_text(resultado["html"], encoding="utf-8")
    print(f"Progreso del OVA: {resultado['progreso']} ({resultado['campos']})")
    print(f"Informe: {salida}  ({salida.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
