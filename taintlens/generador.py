"""Generador de programas con la respuesta conocida por construcción.

Cada programa es una aplicación Flask (o un script de terminal) pequeña con un dato
no confiable, una cadena de transformaciones, y un punto sensible. La etiqueta
(vulnerable o seguro) sale de cómo se montó el programa, no del analizador.

Aviso honesto: este corpus lo he escrito yo, igual que el analizador. Mide que
el motor es coherente y robusto frente a muchas formas de escribir lo mismo; no
demuestra que funcione igual de bien en cualquier código del mundo real.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

CLASES_BENCH = ("cmd", "sql", "path", "code", "deser", "ssrf", "xss", "ssti", "redirect")
CLASES_CLI = ("cmd", "code", "deser")

FUENTES_WEB = [
    'request.args.get("q", "")', 'request.args["q"]', 'request.form["q"]', 'request.values.get("q")',
    'request.headers.get("X-Q", "")', 'request.cookies.get("q", "")', '(request.get_json() or {}).get("q", "")',
    'request.data.decode()', 'request.form.get("q")',
]
FUENTES_CLI = ["sys.argv[1]", "input()", "sys.argv[-1]"]

CABECERA = """import os, sys, subprocess, sqlite3, pickle, json, html, shlex, re, ast, base64, marshal, yaml
import requests, urllib.request
from urllib.parse import urlparse, quote
from flask import Flask, request, redirect, render_template_string, send_file, jsonify, abort, url_for
from markupsafe import escape
from werkzeug.utils import secure_filename
app = Flask(__name__)
BASE = "/srv/datos"
PERMITIDOS = ("alfa", "beta", "gamma")
"""


@dataclass
class Caso:
    id: str
    codigo: str
    clase: str
    vulnerable: bool
    variante: str
    categoria: str
    modo: str = "web"


# ----------------------------------------------------------------------------
# Cadenas de transformación: conservan el dato contaminado en `v`
# ----------------------------------------------------------------------------

def _cadena(rng: random.Random, n: int, uid: str):
    """Devuelve (funciones auxiliares, líneas del cuerpo, nombres de transformaciones)."""
    ayudas: list[str] = []
    lineas: list[str] = []
    usadas: list[str] = []
    for i in range(n):
        k = rng.choice(["alias", "strip", "prefijo", "dict", "lista", "tupla", "ayuda", "clase", "ternario",
                        "bucle", "try", "rama", "compre", "kwargs", "walrus", "slicing", "encadena", "ayuda2"])
        usadas.append(k)
        nm = f"{uid}{i}"
        if k == "alias":
            lineas += [f"w{nm} = v", f"v = w{nm}"]
        elif k == "strip":
            lineas.append(rng.choice(["v = v.strip()", "v = v.lower()", "v = v.replace('x', 'y')", "v = v.title()"]))
        elif k == "prefijo":
            lineas.append(rng.choice(['v = "ok-" + v', 'v = f"{v}"', 'v = "%s" % v', 'v = "{}".format(v)',
                                      'v = v + "-fin"', 'v = "".join([v, ""])']))
        elif k == "dict":
            lineas += [f'd{nm} = {{"k": v, "z": "const"}}', f'v = d{nm}["k"]']
        elif k == "lista":
            lineas += [f'l{nm} = [v, "const"]', f"v = l{nm}[0]"]
        elif k == "tupla":
            lineas += [f'a{nm}, b{nm} = v, "const"', f"v = a{nm}"]
        elif k == "ayuda":
            ayudas.append(f"def ayuda_{nm}(x):\n    y = x.strip()\n    return y\n")
            lineas.append(f"v = ayuda_{nm}(v)")
        elif k == "ayuda2":
            ayudas.append(f"def interna_{nm}(x):\n    return x + ''\n\ndef externa_{nm}(x):\n    return interna_{nm}(x)\n")
            lineas.append(f"v = externa_{nm}(v)")
        elif k == "clase":
            ayudas.append(f"class Caja{nm}:\n    def __init__(self, dato):\n        self.dato = dato\n\n"
                          f"    def obtener(self):\n        return self.dato\n")
            lineas += [f"c{nm} = Caja{nm}(v)", f"v = c{nm}.obtener()"]
        elif k == "ternario":
            lineas.append('v = v if v else "defecto"')
        elif k == "bucle":
            lineas += [f"for it{nm} in [v]:", f"    v = it{nm}"]
        elif k == "try":
            lineas += ["try:", "    v = v.strip()", "except Exception:", '    v = "x"']
        elif k == "rama":
            lineas += ['if len(v) > 3:', '    v = v + "a"', 'else:', '    v = v + "b"']
        elif k == "compre":
            lineas.append('v = "".join(c for c in v)')
        elif k == "kwargs":
            ayudas.append(f"def kw_{nm}(a=None, b=None):\n    return a\n")
            lineas.append(f"v = kw_{nm}(b='c', a=v)")
        elif k == "walrus":
            lineas.append(f"v = (t{nm} := v)")
        elif k == "slicing":
            lineas.append("v = v[:200]")
        elif k == "encadena":
            lineas.append('v = v.strip().lower().replace("a", "b")')
    return ayudas, lineas, usadas


# ----------------------------------------------------------------------------
# Puntos sensibles por clase. {v} es la variable. `ret` si es un return en la ruta.
# ----------------------------------------------------------------------------

SUMIDEROS = {
    "cmd": [
        ('os.system("ping -c 1 " + {v})', False), ('subprocess.run("ls " + {v}, shell=True)', False),
        ('os.popen(f"cat {{{v}}}").read()', False), ('subprocess.check_output("echo %s" % {v}, shell=True)', False),
        ('subprocess.Popen("grep x " + {v}, shell=True)', False), ('subprocess.call({v}, shell=True)', False),
    ],
    "sql": [
        ('cur.execute("SELECT * FROM t WHERE n = \'" + {v} + "\'")', False),
        ('cur.execute(f"SELECT * FROM t WHERE n = \'{{{v}}}\'")', False),
        ('cur.execute("SELECT * FROM t WHERE n = \'%s\'" % {v})', False),
        ('cur.execute("SELECT * FROM t WHERE n = \'{{}}\'".format({v}))', False),
        ('cur.executescript("DELETE FROM t WHERE n = " + {v})', False),
    ],
    "path": [
        ('open("/data/" + {v}).read()', False), ('open({v}).read()', False), ('os.remove({v})', False),
        ('send_file({v})', False), ('os.listdir("/tmp/" + {v})', False),
    ],
    "code": [('eval({v})', False), ('exec({v})', False), ('eval("2 * " + {v})', False), ('exec(f"x = {{{v}}}")', False),
             ('compile({v}, "<s>", "exec")', False)],
    "deser": [('pickle.loads({v}.encode())', False), ('pickle.loads(base64.b64decode({v}))', False),
              ('yaml.load({v})', False), ('marshal.loads({v}.encode())', False),
              ('yaml.load({v}, Loader=yaml.Loader)', False)],
    "ssrf": [('requests.get({v})', False), ('requests.post({v}, data={{}})', False),
             ('urllib.request.urlopen({v})', False), ('requests.get("http://" + {v})', False),
             ('requests.get(url={v})', False)],
    "xss": [('"<h1>" + {v} + "</h1>"', True), ('f"<p>{{{v}}}</p>"', True), ('"<p>%s</p>" % {v}', True),
            ('"<p>{{}}</p>".format({v})', True), ('"<div>" + {v}', True)],
    "ssti": [('render_template_string({v})', False), ('render_template_string("<p>" + {v} + "</p>")', False),
             ('render_template_string(f"Hola {{{v}}}")', False)],
    "redirect": [('redirect({v})', False), ('redirect({v} + "?ok=1")', False), ('redirect(location={v})', False)],
}

PREPARACION = {"sql": ["cur = sqlite3.connect('db.sqlite').cursor()"]}

# variantes seguras con otro punto sensible (el sumidero «seguro» no usa el dato peligrosamente)
SUMIDEROS_SEGUROS = {
    "sql": ['cur.execute("SELECT * FROM t WHERE n = ?", ({v},))', 'cur.execute("SELECT * FROM t WHERE n = %s", [{v}])',
            'cur.execute("SELECT * FROM t WHERE n = :n", {{"n": {v}}})'],
    "code": ["ast.literal_eval({v})", "json.loads({v})"],
    "deser": ["json.loads({v})", "yaml.safe_load({v})", "yaml.load({v}, Loader=yaml.SafeLoader)"],
    "ssti": ['render_template_string("<p>{{{{ x }}}}</p>", x={v})'],
    "xss": ['jsonify({{"q": {v}}})'],
    "cmd": ['subprocess.run(["ls", "-l"], check=True)'],
    "ssrf": ['requests.get("https://api.example.com/items/" + {v})', 'requests.get(f"https://api.example.com/{{{v}}}")'],
    "redirect": ['redirect(url_for("inicio"))', 'redirect("/panel/" + {v})'],
    "path": [],
}


def _sumidero(rng, clase: str, v: str, seguro_alt: bool = False):
    if seguro_alt:
        plantilla = rng.choice(SUMIDEROS_SEGUROS[clase])
        ret = clase in ("redirect", "xss")
        return plantilla.format(v=v), ret
    plantilla, ret = rng.choice(SUMIDEROS[clase])
    return plantilla.format(v=v), ret


# ----------------------------------------------------------------------------
# Neutralizaciones
# ----------------------------------------------------------------------------

def _guardia_permitidos(v: str, modo: str):
    if modo == "web":
        return [f"if {v} not in PERMITIDOS:", '    return "no permitido", 400']
    return [f"if {v} not in PERMITIDOS:", "    sys.exit(1)"]


def _seguras(rng, clase: str, v: str, modo: str, uid: str):
    """[(variante, ayudas, líneas previas, sumidero_seguro_alternativo)]"""
    opciones = []
    opciones.append(("guarda_lista", [], _guardia_permitidos(v, modo), False))
    opciones.append(("constante", [], ['v = "constante"'], False))
    if clase in ("cmd", "sql", "code", "path", "xss", "ssti", "redirect", "ssrf"):
        opciones.append(("cast_int", [], ["v = str(int(v))"], False))
    if clase in ("cmd", "sql", "path", "code", "xss", "deser", "redirect", "ssrf"):
        opciones.append(("isdigit", [], [f"if not {v}.isdigit():", '    return "bad", 400' if modo == "web" else "    sys.exit(1)"], False))
    if clase in ("cmd",):
        opciones.append(("shlex_quote", [], ["v = shlex.quote(v)"], False))
        opciones.append(("ayuda_sanea", [f"def limpia_{uid}(x):\n    return shlex.quote(x)\n"], [f"v = limpia_{uid}(v)"], False))
        opciones.append(("regex_completa", [], ['if not re.fullmatch(r"[a-z0-9.]+", v):', '    return "no", 400' if modo == "web" else "    sys.exit(1)"], False))
    if clase in ("sql", "code", "deser", "ssti", "xss", "cmd", "ssrf", "redirect"):
        if SUMIDEROS_SEGUROS.get(clase):
            opciones.append(("sumidero_seguro", [], [], True))
    if clase == "path":
        opciones.append(("basename", [], ["v = os.path.basename(v)"], False))
        opciones.append(("secure_filename", [], ["v = secure_filename(v)"], False))
        opciones.append(("realpath_guarda", [], ["v = os.path.realpath(os.path.join(BASE, v))",
                                                 'if not v.startswith(BASE + "/"):', '    abort(403)'], False))
        opciones.append(("ayuda_sanea", [f"def limpia_{uid}(x):\n    return os.path.basename(x)\n"], [f"v = limpia_{uid}(v)"], False))
    if clase == "xss":
        opciones.append(("html_escape", [], ["v = html.escape(v)"], False))
        opciones.append(("markupsafe_escape", [], ["v = str(escape(v))"], False))
        opciones.append(("ayuda_sanea", [f"def limpia_{uid}(x):\n    return html.escape(x)\n"], [f"v = limpia_{uid}(v)"], False))
    if clase == "ssrf":
        opciones.append(("guarda_host", [], ['if urlparse(v).hostname not in ("api.example.com", "cdn.example.com"):',
                                             '    abort(400)'], False))
    if clase == "redirect":
        opciones.append(("guarda_prefijo", [], ['if not v.startswith("/panel/"):', '    abort(400)'], False))
    if clase == "ssti":
        opciones.append(("cast_int2", [], ["v = str(int(v))"], False))
    return opciones


def _vulnerables(rng, clase: str, v: str, modo: str, uid: str):
    ops = []
    ops.append(("directa", [], [], False))
    legitimo = {"cmd": "shlex.quote(v)", "sql": "html.escape(v)", "path": "os.path.basename(v)",
                "code": "ast.literal_eval(v)", "deser": "html.escape(v)", "ssrf": "html.escape(v)",
                "xss": "html.escape(v)", "ssti": "str(int(v))", "redirect": "html.escape(v)"}
    # señuelo: el dato limpio se calcula pero se usa el original
    ops.append(("senuelo", [], [f"limpio_{uid} = {legitimo[clase] if clase not in ('code',) else 'html.escape(v)'}"], False))
    # saneador de otra clase
    mal = {"cmd": "html.escape(v)", "sql": "os.path.basename(v)", "path": "html.escape(v)",
           "code": "html.escape(v)", "deser": "html.escape(v)", "ssrf": "html.escape(v)",
           "xss": "shlex.quote(v)", "ssti": "html.escape(v)", "redirect": "html.escape(v)"}
    ops.append(("saneador_equivocado", [], [f"v = {mal[clase]}"], False))
    # la guarda no corta el flujo
    ops.append(("guarda_no_corta", [], [f"if {v} not in PERMITIDOS:", '    print("aviso: valor raro")'], False))
    ops.append(("guarda_otra_variable", [], ['otro = "alfa"', "if otro not in PERMITIDOS:", '    return "no", 400'
                                             if modo == "web" else "    sys.exit(1)"], False))
    # se vuelve a contaminar después de sanear
    nuevo = {"web": 'request.args.get("z", "")', "cli": "sys.argv[-1]"}[modo]
    base_san = {"cmd": "shlex.quote(v)", "sql": "html.escape(v)", "path": "os.path.basename(v)",
                "code": "html.escape(v)", "deser": "html.escape(v)", "ssrf": "html.escape(v)",
                "xss": "html.escape(v)", "ssti": "html.escape(v)", "redirect": "html.escape(v)"}
    if clase in ("cmd", "path", "xss"):
        ops.append(("recontamina", [], [f"v = {base_san[clase]}", f"v = v + {nuevo}"], False))
    # solo se sanea en una rama
    if clase in ("cmd", "path", "xss"):
        ops.append(("solo_una_rama", [], ["if len(v) > 5:", f"    v = {base_san[clase]}"], False))
    if clase == "path":
        ops.append(("reemplazo_ingenuo", [], ['v = v.replace("..", "")'], False))
        ops.append(("guarda_ruta_no_corta", [], ['if ".." in v:', '    print("cuidado")'], False))
    if clase == "sql":
        ops.append(("quita_comilla", [], ["v = v.replace(\"'\", \"\")"], False))
    if clase == "redirect":
        ops.append(("startswith_barra", [], ['if not v.startswith("/"):', '    abort(400)'], False))
    if clase == "ssrf":
        ops.append(("guarda_prefijo_debil", [], ['if "example" not in v:', '    abort(400)'], False))
    if clase == "deser":
        ops.append(("loader_inseguro", [], [], False))
    return ops


# ----------------------------------------------------------------------------

def generar(clase: str, vulnerable: bool, rng: random.Random, indice: int) -> Caso:
    uid = f"{indice:04d}"
    modo = "cli" if (clase in CLASES_CLI and rng.random() < 0.18) else "web"
    fuente = rng.choice(FUENTES_CLI if modo == "cli" else FUENTES_WEB)
    n = rng.choice([0, 0, 1, 1, 2, 3, 4])
    ayudas, cadena, usadas = _cadena(rng, n, f"c{uid}")

    envolver = rng.random() < 0.28                       # el sumidero va dentro de una función auxiliar
    variantes = _vulnerables(rng, clase, "v", modo, uid) if vulnerable else _seguras(rng, clase, "v", modo, uid)
    variante, ayudas_neutral, previas, alt = rng.choice(variantes)
    sumi, ret = _sumidero(rng, clase, "v", seguro_alt=alt)
    if variante == "loader_inseguro":
        sumi, ret = "yaml.load(v, Loader=yaml.Loader)", False
    if variante == "sumidero_seguro" and not vulnerable and clase == "xss":
        ret = False
    prep = PREPARACION.get(clase, [])

    ayudas = ayudas + ayudas_neutral
    cuerpo = [f"v = {fuente}"] + cadena + previas
    if envolver and variante not in ("sumidero_seguro",):
        # el punto sensible vive en una función auxiliar que recibe el dato
        sumi_x, ret_x = _sumidero(rng, clase, "x", seguro_alt=False)
        if variante == "loader_inseguro":
            sumi_x, ret_x = "yaml.load(x, Loader=yaml.Loader)", False
        aux = [f"def aplicar_{uid}(x):"] + [f"    {p}" for p in prep]
        if ret_x:
            aux.append(f"    return {sumi_x}")
        elif clase == "redirect":
            aux.append(f"    return {sumi_x}")
        else:
            aux.append(f"    {sumi_x}")
            aux.append('    return "ok"')
        ayudas = ayudas + ["\n".join(aux) + "\n"]
        cuerpo.append(f"return aplicar_{uid}(v)" if modo == "web" else f"aplicar_{uid}(v)")
        categoria = "interprocedural"
    else:
        cuerpo += prep
        if modo == "web":
            if ret or clase == "redirect":
                cuerpo.append(f"return {sumi}")
            else:
                cuerpo.append(sumi)
                cuerpo.append('return "ok"')
        else:
            cuerpo.append(sumi)
        categoria = "directo" if n == 0 else "cadena"
    if not vulnerable:
        categoria = "negativo:" + variante
    else:
        categoria = f"{categoria}|{variante}"

    cab = CABECERA
    if modo == "web":
        cod = cab + "\n" + "\n".join(ayudas) + "\n"
        cod += '@app.route("/r", methods=["GET", "POST"])\ndef vista():\n'
        cod += "\n".join("    " + l if l else l for l in cuerpo) + "\n"
    else:
        cod = cab + "\n" + "\n".join(ayudas) + "\n"
        cod += "def principal():\n" + "\n".join("    " + l for l in cuerpo) + "\n\n"
        cod += 'if __name__ == "__main__":\n    principal()\n'
    return Caso(f"{clase}-{uid}-{'V' if vulnerable else 'S'}", cod, clase, vulnerable, variante, categoria, modo)


def generar_corpus(n_por_clase: int, semilla: int = 1, clases=CLASES_BENCH) -> list[Caso]:
    rng = random.Random(semilla)
    casos = []
    k = 0
    for clase in clases:
        for i in range(n_por_clase):
            casos.append(generar(clase, i % 2 == 0, rng, k))
            k += 1
    return casos
