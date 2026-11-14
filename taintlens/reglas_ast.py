"""Reglas que no necesitan seguir datos: basta con mirar la forma del código."""
from __future__ import annotations

import ast
import re

from .catalogo import REGLAS
from .modelo import Hallazgo, Paso
from .motor import descomponer, huella
from .proyecto import Modulo, Proyecto

NOMBRE_SECRETO = re.compile(
    r"(passw(or)?d|passwd|pwd|secret|api[_-]?key|apikey|token|auth[_-]?key|private[_-]?key|access[_-]?key|"
    r"client[_-]?secret|credential|bearer)", re.I)
VALOR_FALSO = re.compile(r"(example|changeme|change_me|your|xxx|todo|placeholder|dummy|test|<|>|\$\{|\{\{|%s|"
                         r"\*\*\*|none|null|secret_key_here|insert|replace)", re.I)
PATRONES_TOKEN = [
    ("clave de acceso de AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("clave de API tipo «sk-»", re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b")),
    ("token de GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("token de Slack", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b")),
    ("clave de API de Google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("clave privada", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
]


def _qn(m: Modulo, n) -> str | None:
    base, attrs, _ = descomponer(n)
    if base is None:
        return None
    if base in m.imports:
        return ".".join([m.imports[base]] + attrs)
    return ".".join([base] + attrs) if not attrs else None


def _paso(m: Modulo, n, texto: str) -> Paso:
    ln = getattr(n, "lineno", 1)
    cod = m.lineas[ln - 1].strip()[:160] if 0 < ln <= len(m.lineas) else ""
    return Paso(m.ruta, ln, getattr(n, "col_offset", 0), cod, texto)


def _hallazgo(m: Modulo, n, clase: str, mensaje: str, confianza: str = "alta") -> Hallazgo:
    r = REGLAS[clase]
    p = _paso(m, n, mensaje)
    h = Hallazgo(r.id, clase, r.titulo, r.cwe, r.severidad, confianza, m.ruta, p.linea, p.col, p.codigo,
                 mensaje, r.remedio, "", [p], owasp=r.owasp)
    h.huella = huella(h)
    return h


def _kw(call: ast.Call, nombre: str):
    for k in call.keywords:
        if k.arg == nombre:
            return k.value
    return None


def _es_falso(v) -> bool:
    return isinstance(v, ast.Constant) and v.value is False


def _es_verdadero(v) -> bool:
    return isinstance(v, ast.Constant) and v.value is True


NOMBRE_NO_SECRETO = re.compile(r"(_|^)(type|name|id|url|uri|path|file|header|field|len|length|prefix|suffix|mode|class|"
                               r"kind|label|regex|pattern|env|var|param|arg|placeholder|endpoint|host|dir)$", re.I)
IDENTIFICADOR = re.compile(r"^[A-Za-z]+([-_.#:/ ][A-Za-z]+)+$")


def _entropia(v: str) -> float:
    from math import log2
    n = len(v)
    return -sum((v.count(c) / n) * log2(v.count(c) / n) for c in set(v))


def _parece_secreto(valor: str, nombre: str = "") -> bool:
    v = valor.strip()
    if len(v) < 8 or (" " in v and len(v.split()) > 3):
        return False
    if nombre and NOMBRE_NO_SECRETO.search(nombre):
        return False
    if VALOR_FALSO.search(v) or IDENTIFICADOR.match(v):
        return False
    if v.startswith(("http://", "https://", "/", "./")) or v.endswith((".py", ".txt", ".json")):
        return False
    tiene_digito = any(c.isdigit() for c in v)
    tiene_letra = any(c.isalpha() for c in v)
    if tiene_digito and tiene_letra:
        return True
    return len(v) >= 20 and _entropia(v) >= 3.8


def analizar_modulo(m: Modulo) -> list[Hallazgo]:
    out: list[Hallazgo] = []
    es_settings = m.ruta.rsplit("/", 1)[-1].startswith("settings")
    for n in ast.walk(m.arbol):
        if isinstance(n, ast.Assign):
            _asignacion(m, n, out, es_settings)
        elif isinstance(n, ast.AnnAssign) and n.value is not None:
            _asignacion(m, ast.Assign(targets=[n.target], value=n.value, lineno=n.lineno,
                                      col_offset=n.col_offset), out, es_settings)
        elif isinstance(n, ast.Call):
            _llamada(m, n, out)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and len(n.value) < 5000:
            for nombre, rx in PATRONES_TOKEN:
                if rx.search(n.value):
                    out.append(_hallazgo(m, n, "secreto", f"Parece una {nombre} escrita en el código."))
                    break
    return out


def _asignacion(m: Modulo, n: ast.Assign, out, es_settings: bool) -> None:
    for tg in n.targets:
        nombre = tg.id if isinstance(tg, ast.Name) else tg.attr if isinstance(tg, ast.Attribute) else None
        if isinstance(tg, ast.Subscript) and isinstance(tg.slice, ast.Constant) and isinstance(tg.slice.value, str):
            nombre = tg.slice.value
        if not nombre:
            continue
        v = n.value
        if isinstance(v, ast.Constant) and isinstance(v.value, str) and NOMBRE_SECRETO.search(nombre) \
                and _parece_secreto(v.value, nombre):
            out.append(_hallazgo(m, n, "secreto", f"«{nombre}» tiene un valor fijo en el código."))
        if es_settings and nombre == "DEBUG" and _es_verdadero(v):
            out.append(_hallazgo(m, n, "debug", "DEBUG = True en un archivo de configuración."))
        if nombre == "check_hostname" and _es_falso(v):
            out.append(_hallazgo(m, n, "tls", "check_hostname desactivado."))
        if nombre == "verify_mode" and "CERT_NONE" in ast.unparse(v):
            out.append(_hallazgo(m, n, "tls", "verify_mode = CERT_NONE: no se comprueba el certificado."))
        if nombre in ("verify",) and _es_falso(v):
            out.append(_hallazgo(m, n, "tls", "verify = False: no se comprueba el certificado."))
    if isinstance(n.value, ast.Dict):
        for k, v in zip(n.value.keys, n.value.values):
            if isinstance(k, ast.Constant) and isinstance(k.value, str) and NOMBRE_SECRETO.search(k.value) \
                    and isinstance(v, ast.Constant) and isinstance(v.value, str) and _parece_secreto(v.value, k.value):
                out.append(_hallazgo(m, k, "secreto", f"«{k.value}» tiene un valor fijo en el código."))


def _llamada(m: Modulo, n: ast.Call, out) -> None:
    qn = _qn(m, n.func)
    base, attrs, _ = descomponer(n.func)
    cola = attrs[-1] if attrs else base
    # claves por palabra clave: connect(password="...")
    for k in n.keywords:
        if k.arg and NOMBRE_SECRETO.search(k.arg) and isinstance(k.value, ast.Constant) \
                and isinstance(k.value.value, str) and _parece_secreto(k.value.value, k.arg):
            out.append(_hallazgo(m, k.value, "secreto", f"El argumento «{k.arg}» tiene un valor fijo en el código."))
    # TLS
    if _es_falso(_kw(n, "verify") or ast.Constant(value=True)):
        out.append(_hallazgo(m, n, "tls", "Se llama con verify=False: no se comprueba el certificado."))
    if qn in ("ssl._create_unverified_context", "ssl._create_stdlib_context"):
        out.append(_hallazgo(m, n, "tls", "Contexto SSL sin verificación de certificados."))
    if _es_falso(_kw(n, "check_hostname") or ast.Constant(value=True)):
        out.append(_hallazgo(m, n, "tls", "check_hostname=False."))
    # debug
    if cola == "run" and _es_verdadero(_kw(n, "debug")):
        out.append(_hallazgo(m, n, "debug", "El servidor se arranca con debug=True."))
    # JWT
    if qn in ("jwt.decode", "jose.jwt.decode") or (cola == "decode" and base == "jwt"):
        opts = _kw(n, "options")
        if isinstance(opts, ast.Dict):
            for k, v in zip(opts.keys, opts.values):
                if isinstance(k, ast.Constant) and k.value == "verify_signature" and _es_falso(v):
                    out.append(_hallazgo(m, n, "jwt", "jwt.decode con verify_signature=False."))
        if _es_falso(_kw(n, "verify") or ast.Constant(value=True)):
            out.append(_hallazgo(m, n, "jwt", "jwt.decode con verify=False."))
        alg = _kw(n, "algorithms")
        if isinstance(alg, (ast.List, ast.Tuple)) and any(
                isinstance(e, ast.Constant) and str(e.value).lower() == "none" for e in alg.elts):
            out.append(_hallazgo(m, n, "jwt", "Se acepta el algoritmo «none»: los tokens no llevan firma."))
    # hash débil
    if qn in ("hashlib.md5", "hashlib.sha1") and not _es_falso(_kw(n, "usedforsecurity") or ast.Constant(value=True)):
        out.append(_hallazgo(m, n, "hash", f"Se usa {qn.split('.')[-1].upper()}.", "media"))
    if qn == "hashlib.new" and n.args and isinstance(n.args[0], ast.Constant) \
            and str(n.args[0].value).lower() in ("md5", "sha1", "md4"):
        out.append(_hallazgo(m, n, "hash", f"Se usa {str(n.args[0].value).upper()}.", "media"))
    # yaml
    if qn in ("yaml.load", "yaml.load_all"):
        v = _kw(n, "Loader") or (n.args[1] if len(n.args) > 1 else None)
        if v is None or ast.unparse(v).split(".")[-1] not in ("SafeLoader", "CSafeLoader", "BaseLoader"):
            out.append(_hallazgo(m, n, "yaml_inseguro", "yaml.load sin un cargador seguro."))
    # shell=True con comando dinámico
    if qn in ("subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
              "subprocess.Popen", "os.system", "os.popen") or qn == "subprocess.getoutput":
        sh = _kw(n, "shell")
        if (sh is not None and not _es_falso(sh)) or qn in ("os.system", "os.popen", "subprocess.getoutput"):
            a0 = n.args[0] if n.args else _kw(n, "args")
            if a0 is not None and not (isinstance(a0, ast.Constant) and isinstance(a0.value, str)):
                msg = ("El comando se construye en tiempo de ejecución y se ejecuta con un shell"
                       + ("; aunque lo protejas con shlex.quote, subprocess.run con lista es más seguro."
                          if qn.startswith("os.") else "."))
                out.append(_hallazgo(m, n, "shell_true", msg, "media"))
    # temporales
    if qn == "tempfile.mktemp":
        out.append(_hallazgo(m, n, "tmp", "tempfile.mktemp no es seguro."))
    # permisos
    if qn in ("os.chmod", "os.fchmod", "os.makedirs", "os.mkdir", "os.umask"):
        modo = None
        if qn == "os.chmod" and len(n.args) > 1:
            modo = n.args[1]
        elif qn in ("os.makedirs", "os.mkdir"):
            modo = _kw(n, "mode") or (n.args[1] if len(n.args) > 1 else None)
        if isinstance(modo, ast.Constant) and isinstance(modo.value, int) and modo.value & 0o002:
            out.append(_hallazgo(m, n, "permisos", f"Permisos {oct(modo.value)}: cualquiera puede escribir."))
    # trust_remote_code
    if _es_verdadero(_kw(n, "trust_remote_code") or ast.Constant(value=False)):
        out.append(_hallazgo(m, n, "codigo_remoto", "trust_remote_code=True ejecuta código del repositorio del modelo."))


def analizar(proyecto: Proyecto) -> list[Hallazgo]:
    out: list[Hallazgo] = []
    for nombre in sorted(proyecto.modulos):
        out.extend(analizar_modulo(proyecto.modulos[nombre]))
    return out
