"""Construcciones del lenguaje, saneadores, guardas y sumideros."""
import pytest

from conftest import clases, hallazgos, ids

CAB = ("import os, sys, subprocess, sqlite3, pickle, yaml, re, shlex, html, ast, json, logging, tempfile\n"
       "import requests, urllib.request\n"
       "from flask import request, redirect, render_template_string, send_file\n"
       "from lxml import etree\n")


def prog(cuerpo: str) -> str:
    return CAB + "def h():\n" + "\n".join("    " + l for l in cuerpo.strip("\n").split("\n")) + "\n"


# --------------------------------------------------------------------------------------
# propagación a través de construcciones del lenguaje
# --------------------------------------------------------------------------------------
PROPAGA = {
    "asignacion": "v = request.args['x']\nos.system(v)",
    "alias": "v = request.args['x']\nw = v\nos.system(w)",
    "aug": "v = 'a'\nv += request.args['x']\nos.system(v)",
    "concat": "os.system('ls ' + request.args['x'])",
    "fstring": "v = request.args['x']\nos.system(f'ls {v}')",
    "percent": "os.system('ls %s' % request.args['x'])",
    "format": "os.system('ls {}'.format(request.args['x']))",
    "join": "os.system(' '.join(['ls', request.args['x']]))",
    "lista_indice": "l = ['a', request.args['x']]\nos.system(l[1])",
    "dict_indice": "d = {'k': request.args['x']}\nos.system(d['k'])",
    "dict_dinamico": "d = {}\nd['k'] = request.args['x']\nos.system(d['k'])",
    "tupla": "a, b = request.args['x'], 'c'\nos.system(a)",
    "tupla_estrella": "a, *b = request.args.getlist('x')\nos.system(a)",
    "ternario": "v = request.args['x'] if request else 'a'\nos.system(v)",
    "bucle_for": "for v in request.args.getlist('x'):\n    os.system(v)",
    "bucle_while": "v = request.args['x']\nwhile v:\n    os.system(v)\n    break",
    "with": "with open('/tmp/f') as f:\n    v = request.args['x']\n    os.system(v)",
    "try": "try:\n    v = request.args['x']\nexcept Exception:\n    v = ''\nos.system(v)",
    "finally": "try:\n    pass\nfinally:\n    os.system(request.args['x'])",
    "walrus": "if (v := request.args['x']):\n    os.system(v)",
    "comprension": "v = [x for x in request.args.getlist('x')]\nos.system(v[0])",
    "generador": "os.system(''.join(c for c in request.args['x']))",
    "metodo_cadena": "os.system(request.args['x'].strip().lower())",
    "slicing": "os.system(request.args['x'][:10])",
    "rama_if": "v = 'a'\nif request.args:\n    v = request.args['x']\nos.system(v)",
    "rama_else": "if request.args.get('m'):\n    v = 'a'\nelse:\n    v = request.args['x']\nos.system(v)",
    "match": "match request.args['x']:\n    case v:\n        os.system(v)",
    "atributo_objeto": "o = type('O', (), {})()\no.cmd = request.args['x']\nos.system(o.cmd)",
    "kwargs_llamada": "os.system(command=request.args['x'])",
    "estrella_args": "os.system(*[request.args['x']])",
    "bytes_decode": "os.system(request.data.decode())",
    "setdefault": "d = {}\nd.setdefault('k', request.args['x'])\nos.system(d['k'])",
    "append": "l = []\nl.append(request.args['x'])\nos.system(l[0])",
    "extend": "l = []\nl.extend(request.args.getlist('x'))\nos.system(l[0])",
    "encadenado": "a = request.args['x']\nb = a\nc = b\nd = c\nos.system(d)",
}


@pytest.mark.parametrize("nombre", sorted(PROPAGA))
def test_propaga(nombre):
    assert "cmd" in clases(prog(PROPAGA[nombre])), nombre


NO_PROPAGA = {
    "constante": "os.system('ls')",
    "int": "os.system('sleep %d' % int(request.args['x']))",
    "float": "os.system('sleep %f' % float(request.args['x']))",
    "len": "os.system('sleep %d' % len(request.args['x']))",
    "comparacion": "os.system('echo si' if request.args['x'] == 'a' else 'echo no')",
    "sobreescritura": "v = request.args['x']\nv = 'fijo'\nos.system(v)",
    "isdigit_guarda": "v = request.args['x']\nif v.isdigit():\n    os.system('sleep ' + v)",
    "isdigit_corta": "v = request.args['x']\nif not v.isdigit():\n    return\nos.system('sleep ' + v)",
    "lista_blanca": "v = request.args['x']\nif v in ('a', 'b'):\n    os.system('echo ' + v)",
    "lista_blanca_corta": "v = request.args['x']\nif v not in ('a', 'b'):\n    raise ValueError()\nos.system('echo ' + v)",
    "igualdad": "v = request.args['x']\nif v == 'a':\n    os.system('echo ' + v)",
    "fullmatch": "v = request.args['x']\nif not re.fullmatch('[a-z]+', v):\n    return\nos.system('echo ' + v)",
    "dict_otra_clave": "d = {'a': request.args['x'], 'b': 'ls'}\nos.system(d['b'])",
    "bool": "os.system('echo ' + str(bool(request.args['x'])))",
    "hexdigest": "import hashlib\nos.system('echo ' + hashlib.sha256(request.data).hexdigest())",
    "isinstance_numerico": "v = request.args['x']\nif isinstance(v, int):\n    os.system('sleep %d' % v)",
    "exit_corta": "v = request.args['x']\nif v not in ('a', 'b'):\n    sys.exit(1)\nos.system('echo ' + v)",
}


@pytest.mark.parametrize("nombre", sorted(NO_PROPAGA))
def test_no_propaga(nombre):
    assert "cmd" not in clases(prog(NO_PROPAGA[nombre])), nombre


# --------------------------------------------------------------------------------------
# sumideros: uno vulnerable y uno seguro por clase
# --------------------------------------------------------------------------------------
SUMIDEROS = [
    ("cmd", "os.system('x ' + v)", "os.system('x ' + shlex.quote(v))"),
    ("cmd", "subprocess.run('x ' + v, shell=True)", "subprocess.run(['x', 'y'])"),
    ("cmd", "os.popen('x ' + v)", "os.popen('x ' + shlex.quote(v))"),
    ("cmd", "subprocess.check_output(v, shell=True)", "subprocess.check_output(['ls'])"),
    ("cmd", "subprocess.Popen(['sh', '-c', v])", "subprocess.Popen(['ls', '-l'])"),
    ("cmd_arg", "subprocess.run(['git', 'log', v])", "subprocess.run(['git', 'log', '--oneline'])"),
    ("cmd", "subprocess.run([v, '-l'])", "subprocess.run(['ls', '-l'])"),
    ("sql", "sqlite3.connect('d').cursor().execute('SELECT ' + v)",
     "sqlite3.connect('d').cursor().execute('SELECT ?', (v,))"),
    ("sql", "sqlite3.connect('d').execute(f'SELECT {v}')", "sqlite3.connect('d').execute('SELECT 1')"),
    ("sql", "sqlite3.connect('d').executescript('X' + v)", "sqlite3.connect('d').executescript('X')"),
    ("path", "open(v)", "open('/etc/hostname')"),
    ("path", "open('/d/' + v)", "open('/d/' + os.path.basename(v))"),
    ("path", "os.remove(v)", "os.remove('/tmp/a')"),
    ("path", "send_file(v)", "send_file('/tmp/a')"),
    ("path", "os.listdir(v)", "os.listdir('.')"),
    ("path", "os.rename(v, '/tmp/b')", "os.rename('/tmp/a', '/tmp/b')"),
    ("path", "import shutil\nshutil.copy('/tmp/a', v)", "import shutil\nshutil.copy('/tmp/a', '/tmp/b')"),
    ("path", "import pathlib\npathlib.Path(v).read_text()", "import pathlib\npathlib.Path('a').read_text()"),
    ("code", "eval(v)", "eval('1+1')"),
    ("code", "exec(v)", "exec('x = 1')"),
    ("code", "compile(v, 'f', 'exec')", "compile('x', 'f', 'exec')"),
    ("code", "__import__(v)", "__import__('os')"),
    ("code", "import importlib\nimportlib.import_module(v)", "import importlib\nimportlib.import_module('os')"),
    ("deser", "pickle.loads(v.encode())", "json.loads(v)"),
    ("deser", "yaml.load(v)", "yaml.safe_load(v)"),
    ("deser", "yaml.load(v, Loader=yaml.Loader)", "yaml.load(v, Loader=yaml.SafeLoader)"),
    ("deser", "import marshal\nmarshal.loads(v.encode())", "json.loads(v)"),
    ("deser", "import torch\ntorch.load(v)", "import torch\ntorch.load(v, weights_only=True)"),
    ("deser", "import numpy\nnumpy.load(v, allow_pickle=True)", "import numpy\nnumpy.load(v)"),
    ("ssrf", "requests.get(v)", "requests.get('https://api.example.com/')"),
    ("ssrf", "requests.post(v, data={})", "requests.post('https://api.example.com/', data={})"),
    ("ssrf", "urllib.request.urlopen(v)", "urllib.request.urlopen('https://api.example.com/')"),
    ("ssrf", "requests.get(url=v)", "requests.get('https://api.example.com/' + v)"),
    ("ssrf", "requests.get('http://' + v)", "requests.get('https://api.example.com/x/' + v)"),
    ("redirect", "return redirect(v)", "return redirect('/panel/' + v)"),
    ("ssti", "render_template_string(v)", "render_template_string('<p>{{ x }}</p>', x=v)"),
    ("ssti", "render_template_string('<p>' + v)", "render_template_string('<p>ok</p>')"),
    ("xxe", "etree.fromstring(v)", "etree.fromstring('<a/>')"),
    ("regex", "re.compile(v)", "re.compile(re.escape(v))"),
    ("regex", "re.search(v, 'texto')", "re.search('a+', v)"),
    ("log", "logging.getLogger().info('hola ' + v)", "logging.getLogger().info('hola %s', repr(v))"),
    ("log", "logging.warning(v)", "logging.warning('fijo')"),
]


@pytest.mark.parametrize("clase,malo,bueno", SUMIDEROS, ids=[f"{c}:{m[:28]}" for c, m, _ in SUMIDEROS])
def test_sumidero(clase, malo, bueno):
    cuerpo_malo = "v = request.args['x']\n" + malo
    cuerpo_bueno = "v = request.args['x']\n" + bueno
    assert clase in clases(prog(cuerpo_malo)), cuerpo_malo
    assert clase not in clases(prog(cuerpo_bueno)), cuerpo_bueno


def test_xss_en_retorno_flask():
    src = ("from flask import Flask, request\napp = Flask(__name__)\n@app.route('/')\ndef h():\n"
           "    return '<p>' + request.args['n'] + '</p>'\n")
    assert "xss" in clases(src)


def test_xss_escapado():
    src = ("import html\nfrom flask import Flask, request\napp = Flask(__name__)\n@app.route('/')\ndef h():\n"
           "    return '<p>' + html.escape(request.args['n']) + '</p>'\n")
    assert "xss" not in clases(src)


def test_xss_jsonify_no():
    src = ("from flask import Flask, request, jsonify\napp = Flask(__name__)\n@app.route('/')\ndef h():\n"
           "    return jsonify({'n': request.args['n']})\n")
    assert "xss" not in clases(src)


# --------------------------------------------------------------------------------------
# saneadores: cada uno solo neutraliza lo suyo
# --------------------------------------------------------------------------------------
@pytest.mark.parametrize("sanea,clase_neutralizada,sumidero", [
    ("shlex.quote(v)", "cmd", "os.system('x ' + v)"),
    ("os.path.basename(v)", "path", "open('/d/' + v)"),
    ("re.escape(v)", "regex", "re.compile(v)"),
    ("html.escape(v)", "xss", "return '<b>' + v + '</b>'"),
    ("int(v)", "cmd", "os.system('x %d' % v)"),
    ("ast.literal_eval(v)", "code", "eval(v)"),
])
def test_saneador_neutraliza(sanea, clase_neutralizada, sumidero):
    src = ("from flask import Flask, request\napp = Flask(__name__)\n" + CAB +
           "@app.route('/')\ndef h():\n    v = request.args['x']\n    v = " + sanea + "\n    " + sumidero + "\n")
    assert clase_neutralizada not in clases(src)


@pytest.mark.parametrize("sanea,clase_que_sigue,sumidero", [
    ("html.escape(v)", "cmd", "os.system('x ' + v)"),
    ("shlex.quote(v)", "xss", "return '<b>' + v + '</b>'"),
    ("os.path.basename(v)", "cmd", "os.system('x ' + v)"),
    ("shlex.quote(v)", "path", "open('../' + v)"),
    ("html.escape(v)", "path", "open('/d/' + v)"),
    ("html.escape(v)", "code", "eval(v)"),
    ("shlex.quote(v)", "ssti", "render_template_string(v)"),
])
def test_saneador_equivocado_no_neutraliza(sanea, clase_que_sigue, sumidero):
    src = ("from flask import Flask, request\napp = Flask(__name__)\n" + CAB +
           "@app.route('/')\ndef h():\n    v = request.args['x']\n    v = " + sanea + "\n    " + sumidero + "\n")
    assert clase_que_sigue in clases(src)


def test_saneador_senuelo_no_protege():
    assert "cmd" in clases(prog("v = request.args['x']\nlimpio = shlex.quote(v)\nos.system('x ' + v)"))


def test_recontaminacion_tras_sanear():
    assert "cmd" in clases(prog("v = shlex.quote(request.args['x'])\nv = v + request.args['y']\nos.system(v)"))


def test_saneado_en_una_sola_rama():
    assert "cmd" in clases(prog(
        "v = request.args['x']\nif len(v) > 3:\n    v = shlex.quote(v)\nos.system('x ' + v)"))


def test_saneador_en_funcion_auxiliar():
    src = ("import os, shlex\nfrom flask import request\n"
           "def limpia(x):\n    return shlex.quote(x)\n"
           "def h():\n    os.system('x ' + limpia(request.args['a']))\n")
    assert "cmd" not in clases(src)


def test_re_sub_lista_blanca_sanea():
    assert "cmd" not in clases(prog("v = re.sub(r'[^a-z0-9_]', '', request.args['x'])\nos.system('x ' + v)"))


def test_re_sub_lista_con_caracter_peligroso_no_sanea():
    assert "cmd" in clases(prog("v = re.sub(r'[^a-z;]', '', request.args['x'])\nos.system('x ' + v)"))


def test_replace_de_salto_de_linea_sanea_log():
    assert "log" not in clases(prog(
        "v = request.args['x'].replace('\\n', ' ')\nlogging.getLogger().info('hola ' + v)"))


# --------------------------------------------------------------------------------------
# guardas
# --------------------------------------------------------------------------------------
def test_guarda_que_no_corta_no_protege():
    assert "cmd" in clases(prog("v = request.args['x']\nif v not in ('a', 'b'):\n    print('raro')\nos.system(v)"))


def test_guarda_sobre_otra_variable_no_protege():
    assert "cmd" in clases(prog(
        "v = request.args['x']\no = 'a'\nif o not in ('a', 'b'):\n    return\nos.system(v)"))


def test_guarda_startswith_barra_sola_no_protege_redirect():
    assert "redirect" in clases(prog(
        "v = request.args['x']\nif not v.startswith('/'):\n    return\nreturn redirect(v)"))


def test_guarda_startswith_prefijo_largo_protege_redirect():
    assert "redirect" not in clases(prog(
        "v = request.args['x']\nif not v.startswith('/panel/'):\n    return\nreturn redirect(v)"))


def test_guarda_realpath_startswith():
    src = prog("v = os.path.realpath(os.path.join('/srv', request.args['x']))\n"
               "if not v.startswith('/srv/'):\n    raise ValueError()\nopen(v)")
    assert "path" not in clases(src)


def test_guarda_hostname_urlparse():
    src = CAB + ("from urllib.parse import urlparse\ndef h():\n    v = request.args['u']\n"
                 "    if urlparse(v).hostname not in ('a.com',):\n        return\n    requests.get(v)\n")
    assert "ssrf" not in clases(src)


def test_guarda_con_and_en_la_rama_verdadera():
    assert "cmd" not in clases(prog(
        "v = request.args['x']\nif v.isdigit() and len(v) < 5:\n    os.system('sleep ' + v)"))


def test_guarda_con_or_en_la_rama_falsa():
    assert "cmd" not in clases(prog(
        "v = request.args['x']\nif not v.isdigit() or len(v) > 5:\n    return\nos.system('sleep ' + v)"))


def test_guarda_no_afecta_a_otras_clases_distintas_de_todo():
    # startswith solo limpia path/ssrf/redirect, no cmd
    assert "cmd" in clases(prog("v = request.args['x']\nif v.startswith('abc'):\n    os.system('x ' + v)"))


# --------------------------------------------------------------------------------------
# fuentes
# --------------------------------------------------------------------------------------
FUENTES_WEB = ["request.args['x']", "request.args.get('x')", "request.form['x']", "request.values['x']",
               "request.headers['x']", "request.cookies['x']", "request.get_json()['x']", "request.json['x']",
               "request.data", "request.files['x'].filename", "request.url", "request.path"]


@pytest.mark.parametrize("f", FUENTES_WEB)
def test_fuentes_web(f):
    assert "cmd" in clases(prog(f"v = {f}\nos.system(v)"))


@pytest.mark.parametrize("f", ["sys.argv[1]", "input()", "os.environ['X']", "os.getenv('X')", "sys.stdin.read()"])
def test_fuentes_locales_se_reportan_con_gravedad_baja(f):
    hs = [h for h in hallazgos(prog(f"v = {f}\nos.system(v)")) if h.clase == "cmd"]
    assert hs and hs[0].severidad == "media" and hs[0].confianza != "alta"


def test_fuentes_locales_no_disparan_clases_web():
    assert "ssrf" not in clases(prog("requests.get(sys.argv[1])"))
    assert "path" not in clases(prog("open(sys.argv[1])"))
    assert "xss" not in clases(prog("v = input()\nreturn '<p>' + v"))


def test_datos_de_red_no_son_ssrf_ni_path():
    assert "ssrf" not in clases(prog("u = requests.get('https://a.com/l').text\nrequests.get(u)"))
    assert "path" not in clases(prog("n = requests.get('https://a.com/l').text\nopen(n)"))


def test_datos_de_red_si_son_ejecucion():
    assert "code" in clases(prog("c = requests.get('https://a.com/s').text\nexec(c)"))
    assert "deser" in clases(prog("c = requests.get('https://a.com/s').content\npickle.loads(c)"))


def test_salida_de_modelo_a_exec():
    assert "code" in clases("def f(llm):\n    exec(llm.invoke('hola'))\n")


def test_salida_de_openai_a_cmd():
    src = ("import os\nfrom openai import OpenAI\nclient = OpenAI()\ndef f():\n"
           "    r = client.chat.completions.create(model='m', messages=[])\n"
           "    os.system(r.choices[0].message.content)\n")
    assert "cmd" in clases(src)


def test_prompt_con_texto_de_usuario():
    src = ("from flask import request\nfrom openai import OpenAI\nclient = OpenAI()\ndef f():\n"
           "    client.chat.completions.create(model='m', messages=[{'role': 'user', 'content': request.args['q']}])\n")
    assert "llm_prompt" in clases(src)


def test_prompt_constante_no_alerta():
    src = ("from openai import OpenAI\nclient = OpenAI()\ndef f():\n"
           "    client.chat.completions.create(model='m', messages=[{'role': 'user', 'content': 'hola'}])\n")
    assert "llm_prompt" not in clases(src)


def test_fuente_de_archivos_opcional():
    from taintlens.config import Config
    src = "import os\ndef f():\n    d = open('/tmp/x').read()\n    os.system(d)\n"
    assert "cmd" not in clases(src)
    assert "cmd" in clases(src, config=Config(fuentes_archivo=True))


# --------------------------------------------------------------------------------------
# interprocedural
# --------------------------------------------------------------------------------------
def test_interproc_sumidero_en_auxiliar():
    src = ("import os\nfrom flask import request\ndef run(c):\n    os.system(c)\n"
           "def h():\n    run(request.args['c'])\n")
    hs = [h for h in hallazgos(src) if h.clase == "cmd"]
    assert hs and hs[0].linea == 4                       # se informa en el sumidero, no en la llamada
    assert any("run" in p.texto for p in hs[0].traza)     # y la traza pasa por la llamada


def test_interproc_retorno():
    src = ("import os\nfrom flask import request\ndef lee():\n    return request.args['c']\n"
           "def h():\n    os.system(lee())\n")
    assert "cmd" in clases(src)


def test_interproc_dos_niveles():
    src = ("import os\nfrom flask import request\ndef a(x):\n    os.system(x)\ndef b(x):\n    a(x)\n"
           "def c(x):\n    b(x)\ndef h():\n    c(request.args['q'])\n")
    assert "cmd" in clases(src)


def test_interproc_auxiliar_llamada_con_constante_no_alerta():
    src = ("import os\ndef run(c):\n    os.system(c)\ndef h():\n    run('ls')\n")
    assert "cmd" not in clases(src)


def test_interproc_recursion_termina():
    src = ("import os\nfrom flask import request\ndef f(x, n):\n    if n:\n        return f(x, n - 1)\n    return x\n"
           "def h():\n    os.system(f(request.args['c'], 3))\n")
    assert "cmd" in clases(src)


def test_interproc_recursion_mutua_termina():
    src = ("import os\nfrom flask import request\ndef a(x):\n    return b(x)\ndef b(x):\n    return a(x) + x\n"
           "def h():\n    os.system(a(request.args['c']))\n")
    assert "cmd" in clases(src)


def test_interproc_argumentos_con_nombre():
    src = ("import os\nfrom flask import request\ndef run(a, b):\n    os.system(b)\n"
           "def h():\n    run(b=request.args['c'], a='x')\n")
    assert "cmd" in clases(src)


def test_interproc_solo_el_parametro_peligroso():
    src = ("import os\nfrom flask import request\ndef run(a, b):\n    os.system(b)\n"
           "def h():\n    run(request.args['c'], 'x')\n")
    assert "cmd" not in clases(src)


def test_interproc_saneado_dentro_de_la_funcion():
    src = ("import os, shlex\nfrom flask import request\ndef run(c):\n    os.system('x ' + shlex.quote(c))\n"
           "def h():\n    run(request.args['c'])\n")
    assert "cmd" not in clases(src)


def test_interproc_varargs():
    src = ("import os\nfrom flask import request\ndef run(*a):\n    os.system(a[0])\n"
           "def h():\n    run(request.args['c'])\n")
    assert "cmd" in clases(src)


def test_interproc_kwargs():
    src = ("import os\nfrom flask import request\ndef run(**k):\n    os.system(k['c'])\n"
           "def h():\n    run(c=request.args['c'])\n")
    assert "cmd" in clases(src)


def test_funcion_anidada_ve_variables_capturadas():
    src = ("import os\nfrom flask import request\ndef h():\n    v = request.args['c']\n    def f():\n"
           "        os.system(v)\n    f()\n")
    assert "cmd" in clases(src)


def test_lambda():
    src = ("import os\nfrom flask import request\ndef h():\n    f = lambda c: os.system(c)\n"
           "    f(request.args['c'])\n")
    assert "cmd" in clases(src)


def test_hilo_con_target():
    src = ("import os, threading\nfrom flask import request\ndef t(c):\n    os.system(c)\n"
           "def h():\n    threading.Thread(target=t, args=(request.args['c'],)).start()\n")
    assert "cmd" in clases(src)


def test_executor_submit():
    src = ("import os\nfrom flask import request\ndef t(c):\n    os.system(c)\n"
           "def h(ex):\n    ex.submit(t, request.args['c'])\n")
    assert "cmd" in clases(src)


# --------------------------------------------------------------------------------------
# clases, campos y varios módulos
# --------------------------------------------------------------------------------------
def test_campo_escrito_en_init():
    src = ("import os\nfrom flask import request\nclass J:\n    def __init__(self, c):\n        self.c = c\n"
           "    def go(self):\n        os.system(self.c)\ndef h():\n    J(request.args['c']).go()\n")
    assert "cmd" in clases(src)


def test_campo_con_metodo_intermedio():
    src = ("import os\nfrom flask import request\nclass J:\n    def poner(self, c):\n        self.c = c\n"
           "    def go(self):\n        os.system(self.c)\ndef h():\n    j = J()\n    j.poner(request.args['c'])\n    j.go()\n")
    assert "cmd" in clases(src)


def test_herencia():
    src = ("import os\nfrom flask import request\nclass B:\n    def go(self, c):\n        os.system(c)\n"
           "class H(B):\n    def ir(self):\n        self.go(request.args['c'])\ndef h():\n    H().ir()\n")
    assert "cmd" in clases(src)


def test_super():
    src = ("import os\nfrom flask import request\nclass B:\n    def go(self, c):\n        os.system(c)\n"
           "class H(B):\n    def go(self, c):\n        super().go(c)\ndef h():\n    H().go(request.args['c'])\n")
    assert "cmd" in clases(src)


def test_dataclass_sin_init():
    src = ("import os\nfrom dataclasses import dataclass\nfrom flask import request\n@dataclass\nclass T:\n"
           "    orden: str\n    def go(self):\n        os.system(self.orden)\ndef h():\n    T(request.args['c']).go()\n")
    assert "cmd" in clases(src)


def test_metodo_estatico():
    src = ("import os\nfrom flask import request\nclass U:\n    @staticmethod\n    def run(c):\n        os.system(c)\n"
           "def h():\n    U.run(request.args['c'])\n")
    assert "cmd" in clases(src)


def test_multimodulo_funcion():
    assert "cmd" in clases({
        "util.py": "import os\ndef run(c):\n    os.system(c)\n",
        "app.py": "from flask import request\nimport util\ndef h():\n    util.run(request.args['c'])\n"})


def test_multimodulo_import_from():
    assert "cmd" in clases({
        "util.py": "import os\ndef run(c):\n    os.system(c)\n",
        "app.py": "from flask import request\nfrom util import run\ndef h():\n    run(request.args['c'])\n"})


def test_multimodulo_con_alias():
    assert "cmd" in clases({
        "util.py": "import os\ndef run(c):\n    os.system(c)\n",
        "app.py": "from flask import request\nimport util as u\ndef h():\n    u.run(request.args['c'])\n"})


def test_multimodulo_paquete_relativo():
    assert "cmd" in clases({
        "pkg/__init__.py": "",
        "pkg/util.py": "import os\ndef run(c):\n    os.system(c)\n",
        "pkg/app.py": "from flask import request\nfrom .util import run\ndef h():\n    run(request.args['c'])\n"})


def test_multimodulo_clase():
    assert "cmd" in clases({
        "m.py": "import os\nclass R:\n    def go(self, c):\n        os.system(c)\n",
        "app.py": "from flask import request\nfrom m import R\ndef h():\n    R().go(request.args['c'])\n"})


def test_multimodulo_variable_global_contaminada():
    assert "cmd" in clases({
        "cfg.py": "import os\nCMD = os.environ['CMD']\n",
        "app.py": "import os\nfrom cfg import CMD\ndef h():\n    os.system(CMD)\n"})


def test_modulos_con_mismo_nombre_de_archivo():
    r = ids({"a/main.py": "x = 1\n", "b/main.py": "import os\nfrom flask import request\nos.system(request.args['c'])\n"})
    assert "TL101" in r


# --------------------------------------------------------------------------------------
# puntos de entrada
# --------------------------------------------------------------------------------------
def test_entrada_ruta_flask_con_parametro():
    src = ("import os\nfrom flask import Flask\napp = Flask(__name__)\n@app.route('/<n>')\ndef f(n):\n    os.system(n)\n")
    assert "cmd" in clases(src)


def test_entrada_fastapi():
    src = ("import os\nfrom fastapi import FastAPI\napp = FastAPI()\n@app.get('/x')\ndef f(c: str):\n    os.system(c)\n")
    assert "cmd" in clases(src)


def test_entrada_herramienta_mcp():
    src = ("import os\nfrom mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n@mcp.tool()\ndef f(c: str):\n    os.system(c)\n")
    assert "cmd" in clases(src)


def test_entrada_lambda_aws():
    assert "cmd" in clases("import os\ndef lambda_handler(event, context):\n    os.system(event['c'])\n")


def test_entrada_lambda_aws_el_contexto_no_cuenta():
    assert "cmd" not in clases("import os\ndef lambda_handler(event, context):\n    os.system(context.aws_request_id)\n")


def test_entrada_django():
    src = ("import os\nfrom django.http import HttpResponse\ndef v(request):\n    os.system(request.GET['c'])\n")
    assert "cmd" in clases(src)


def test_funcion_normal_no_es_entrada():
    assert "cmd" not in clases("import os\ndef f(c):\n    os.system(c)\n")


def test_entrada_click():
    src = ("import os, click\n@click.command()\n@click.argument('c')\ndef f(c):\n    os.system(c)\n")
    assert "cmd" in clases(src)


# --------------------------------------------------------------------------------------
# trazas y gravedad
# --------------------------------------------------------------------------------------
def test_traza_empieza_en_el_origen_y_acaba_en_el_sumidero():
    h = [h for h in hallazgos(prog("v = request.args['x']\nw = v\nos.system(w)")) if h.clase == "cmd"][0]
    assert "request" in h.traza[0].codigo
    assert "os.system" in h.traza[-1].codigo
    assert h.traza[-1].linea == h.linea
    assert len(h.traza) >= 3


def test_gravedad_web_critica_y_local_baja():
    web = [h for h in hallazgos(prog("os.system(request.args['x'])")) if h.clase == "cmd"][0]
    loc = [h for h in hallazgos(prog("os.system(sys.argv[1])")) if h.clase == "cmd"][0]
    assert web.severidad == "critica" and loc.severidad == "media"


def test_confianza_baja_si_pasa_por_funcion_desconocida():
    src = "import os, extlib\nfrom flask import request\ndef h():\n    os.system(extlib.cosa(request.args['x']))\n"
    h = [h for h in hallazgos(src) if h.clase == "cmd"][0]
    assert h.confianza in ("media", "baja")


def test_estricto_oculta_los_inciertos():
    from taintlens.config import Config
    src = "import os, extlib\nfrom flask import request\ndef h():\n    os.system(extlib.cosa(request.args['x']))\n"
    assert "cmd" in clases(src)
    assert "cmd" not in clases(src, config=Config(estricto=True))


def test_hallazgo_unico_por_origen_y_sumidero():
    src = prog("v = request.args['x']\nif v:\n    v = v + 'a'\nelse:\n    v = v + 'b'\nos.system(v)")
    assert len([h for h in hallazgos(src) if h.clase == "cmd"]) == 1


def test_prefijo_de_ruta_fija_no_es_ssrf_pero_si_path():
    assert "ssrf" not in clases(prog("requests.get('https://a.com/' + request.args['x'])"))
    assert "path" in clases(prog("open('/d/' + request.args['x'])"))


def test_guarda_con_regex_compilada():
    src = ("import re, os\nfrom flask import request\nPAT = re.compile(r'[a-z]+')\ndef h():\n    v = request.args['x']\n"
           "    if not PAT.fullmatch(v):\n        raise ValueError()\n    os.system('echo ' + v)\n")
    assert "cmd" not in clases(src)


def test_doble_guion_antes_del_argumento_no_es_inyeccion_de_argumentos():
    assert "TL102" not in ids(prog("subprocess.run(['ls', '-l', '--', request.args['d']])"))
    assert "TL102" in ids(prog("subprocess.run(['ls', request.args['d']])"))


def test_doble_guion_no_oculta_argumentos_anteriores():
    assert "TL102" in ids(prog("subprocess.run(['ls', request.args['d'], '--', 'x'])"))
