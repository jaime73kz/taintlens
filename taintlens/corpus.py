"""Corpus escrito a mano: estilos de código reales, casos seguros difíciles y limitaciones conocidas.

`espera` dice, por clase, si debe haber hallazgo (True) o no (False). Los casos con
`limitacion=True` son fallos conocidos y documentados: el test comprueba que SIGUEN
fallando, así la documentación no puede quedarse desfasada sin que nadie se entere.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CasoManual:
    id: str
    fuentes: dict
    espera: dict
    nota: str = ""
    limitacion: bool = False


def C(id, codigo, espera, nota="", limitacion=False):
    fuentes = codigo if isinstance(codigo, dict) else {"app.py": codigo}
    return CasoManual(id, fuentes, espera, nota, limitacion)


CASOS: list[CasoManual] = [
    # ---------------------------------------------------------------- vulnerables
    C("v01-django-sql", """
from django.http import HttpResponse
from django.db import connection
def buscar(request):
    q = request.GET["q"]
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM libros WHERE titulo = '%s'" % q)
    return HttpResponse("ok")
""", {"sql": True}, "vista de Django: request es el primer parámetro"),
    C("v02-fastapi-cmd", """
import os
from fastapi import FastAPI
app = FastAPI()
@app.get("/run")
def ejecutar(cmd: str):
    return {"salida": os.popen(cmd).read()}
""", {"cmd": True}),
    C("v03-fastapi-async-ssrf", """
import httpx
from fastapi import FastAPI
app = FastAPI()
@app.get("/proxy")
async def proxy(url: str):
    async with httpx.AsyncClient() as client:
        r = await client.get(url)
    return r.text
""", {"ssrf": True}, "cliente asíncrono: el receptor se llama «client»"),
    C("v04-flask-ruta-path", """
from flask import Flask, send_file
app = Flask(__name__)
@app.route("/f/<nombre>")
def f(nombre):
    return send_file("/datos/" + nombre)
""", {"path": True}, "parámetro de ruta de Flask"),
    C("v05-cli-argparse", """
import argparse, os
p = argparse.ArgumentParser()
p.add_argument("archivo")
args = p.parse_args()
os.system("tar tf " + args.archivo)
""", {"cmd": True}, "origen local (línea de comandos): gravedad menor"),
    C("v06-mcp-sql", """
import sqlite3
from mcp.server.fastmcp import FastMCP
mcp = FastMCP("datos")
conn = sqlite3.connect("x.db")
@mcp.tool()
def consulta(sql: str) -> list:
    return conn.execute(sql).fetchall()
""", {"sql": True}, "el argumento lo elige el modelo"),
    C("v07-llm-a-eval", """
def calcular(llm, pregunta):
    codigo = llm.invoke("Escribe una expresion python para: " + pregunta)
    return eval(codigo)
""", {"code": True}, "salida de un modelo ejecutada"),
    C("v08-openai-a-exec", """
from openai import OpenAI
client = OpenAI()
def agente(t):
    r = client.chat.completions.create(model="m", messages=[{"role": "user", "content": t}])
    codigo = r.choices[0].message.content
    exec(codigo)
""", {"code": True}),
    C("v09-prompt-injection-web", """
import requests
from openai import OpenAI
client = OpenAI()
def resumir(url):
    pagina = requests.get(url, timeout=5).text
    return client.chat.completions.create(model="m", messages=[{"role": "user", "content": "Resume: " + pagina}])
""", {"llm_prompt": True}, "texto de una página web dentro del prompt"),
    C("v10-clase-campo", """
import os
from flask import Flask, request
app = Flask(__name__)
class Trabajo:
    def __init__(self, orden):
        self.orden = orden
    def lanzar(self):
        os.system(self.orden)
@app.route("/t")
def t():
    Trabajo(request.args["o"]).lanzar()
    return "ok"
""", {"cmd": True}),
    C("v11-multimodulo", {
        "util.py": "import subprocess\ndef correr(c):\n    return subprocess.run(c, shell=True)\n",
        "app.py": "from flask import request\nfrom util import correr\ndef h():\n    correr(request.args['c'])\n"},
      {"cmd": True}, "el sumidero está en otro archivo"),
    C("v12-herencia", """
import os
from flask import request
class Base:
    def ejecutar(self, c):
        os.system(c)
class Hija(Base):
    def ir(self):
        self.ejecutar(request.args["c"])
def h():
    Hija().ir()
""", {"cmd": True}),
    C("v13-decorador", """
import functools, os
from flask import request
def registra(f):
    @functools.wraps(f)
    def w(*a, **k):
        return f(*a, **k)
    return w
@registra
def h():
    os.system("echo " + request.args["x"])
""", {"cmd": True}),
    C("v14-lambda-aws", """
import os
def lambda_handler(event, context):
    os.system(event["comando"])
""", {"cmd": True}),
    C("v15-streamlit", """
import streamlit as st
q = st.text_input("Formula")
st.write(eval(q))
""", {"code": True}),
    C("v16-pickle-body", "import pickle\nfrom flask import request\ndef h():\n    return str(pickle.loads(request.data))\n",
      {"deser": True}),
    C("v17-yaml-load", "import yaml\nfrom flask import request\ndef h():\n    return yaml.load(request.data)\n", {"deser": True}),
    C("v18-xxe", "from lxml import etree\nfrom flask import request\ndef h():\n    return etree.fromstring(request.data)\n",
      {"xxe": True}),
    C("v19-redirect", "from flask import redirect, request\ndef h():\n    return redirect(request.args.get('next'))\n",
      {"redirect": True}),
    C("v20-ssti", "from flask import render_template_string, request\ndef h():\n    return render_template_string(request.args['t'])\n",
      {"ssti": True}),
    C("v21-compre-join", """
import os
from flask import request
def h():
    opciones = " ".join(f"--{k}={v}" for k, v in request.args.items())
    os.system("herramienta " + opciones)
""", {"cmd": True}),
    C("v22-log", "import logging\nfrom flask import request\nlog = logging.getLogger()\ndef h():\n    log.info(f\"login {request.args['u']}\")\n",
      {"log": True}),
    C("v23-regex", "import re\nfrom flask import request\ndef h():\n    return re.compile(request.args['p'])\n", {"regex": True}),
    C("v24-retorno-tupla", """
import os
from flask import request
def leer():
    return request.args["a"], request.args["b"]
def h():
    a, b = leer()
    os.system(a)
""", {"cmd": True}),
    C("v25-global-entorno", """
import os
CMD = os.environ["CMD"]
def correr():
    os.system(CMD)
""", {"cmd": True}, "variable global de entorno usada en otra función"),
    C("v26-recursion", """
import os
from flask import request
def pasa(x, n):
    return x if n == 0 else pasa(x, n - 1)
def h():
    os.system(pasa(request.args["c"], 3))
""", {"cmd": True}),
    C("v27-sh-c", "import subprocess\nfrom flask import request\ndef h():\n    subprocess.Popen(['sh', '-c', request.args['c']])\n",
      {"cmd": True}),
    C("v28-sanea-parcial", """
import os, shlex
from flask import request
def h():
    a = shlex.quote(request.args["a"])
    b = request.args["b"]
    os.system("cmd " + a + " " + b)
""", {"cmd": True}, "uno de los dos valores sigue sin sanear"),
    C("v29-starlette-async", """
import os
from fastapi import FastAPI, Request
app = FastAPI()
@app.post("/x")
async def x(request: Request):
    cuerpo = await request.json()
    os.system(cuerpo["cmd"])
""", {"cmd": True}),
    C("v30-trust-remote", """
from transformers import AutoModel
from flask import request
def h():
    return AutoModel.from_pretrained(request.args["m"], trust_remote_code=True)
""", {"deser": True}, "modelo elegido por el usuario con código remoto"),
    # ---------------------------------------------------------------- seguros
    C("s01-sql-parametrizado", """
from django.db import connection
def buscar(request):
    q = request.GET["q"]
    with connection.cursor() as c:
        c.execute("SELECT * FROM libros WHERE titulo = %s", [q])
""", {"sql": False}),
    C("s02-shlex", "import os, shlex\nfrom flask import request\ndef h():\n    os.system('echo ' + shlex.quote(request.args['x']))\n",
      {"cmd": False}),
    C("s03-dispatch", """
from flask import request
def a(): return 1
def b(): return 2
ACCIONES = {"a": a, "b": b}
def h():
    return ACCIONES.get(request.args.get("x"), a)()
""", {"cmd": False, "code": False}),
    C("s04-int", "import os\nfrom flask import request\ndef h():\n    n = int(request.args['n'])\n    os.system('sleep %d' % n)\n",
      {"cmd": False}),
    C("s05-lista-fija", "import subprocess\nfrom flask import request\ndef h():\n    subprocess.run(['git', 'status'], cwd='/srv')\n    return request.args.get('x') and 'ok'\n",
      {"cmd": False}),
    C("s06-escape", "import html\nfrom flask import Flask, request\napp = Flask(__name__)\n@app.route('/')\ndef h():\n    return '<p>' + html.escape(request.args['n']) + '</p>'\n",
      {"xss": False}),
    C("s07-jsonify", "from flask import Flask, request, jsonify\napp = Flask(__name__)\n@app.route('/')\ndef h():\n    return jsonify({'q': request.args['q']})\n",
      {"xss": False}),
    C("s08-secure-filename", "from flask import request, send_file\nfrom werkzeug.utils import secure_filename\ndef h():\n    return send_file('/d/' + secure_filename(request.args['f']))\n",
      {"path": False}),
    C("s09-fullmatch", "import os, re\nfrom flask import request\ndef h():\n    v = request.args['x']\n    if not re.fullmatch(r'[a-z0-9]+', v):\n        raise ValueError('no')\n    os.system('echo ' + v)\n",
      {"cmd": False}),
    C("s10-sanea-en-otro-modulo", {
        "limpio.py": "import shlex\ndef seguro(x):\n    return shlex.quote(x)\n",
        "app.py": "import os\nfrom flask import request\nfrom limpio import seguro\ndef h():\n    os.system('echo ' + seguro(request.args['x']))\n"},
      {"cmd": False}),
    C("s11-host-fijo", "import requests\nfrom flask import request\ndef h():\n    return requests.get('https://api.example.com/items/' + request.args['i']).text\n",
      {"ssrf": False}, "solo cambia la ruta, no el servidor"),
    C("s12-safe-load", "import yaml\nfrom flask import request\ndef h():\n    return yaml.safe_load(request.data)\n", {"deser": False}),
    C("s13-eval-constante", "def h():\n    return eval('1 + 1')\n", {"code": False}),
    C("s14-isdigit", "import os\nfrom flask import request\ndef h():\n    v = request.args['x']\n    if v.isdigit():\n        os.system('sleep ' + v)\n",
      {"cmd": False}),
    C("s15-reasigna-constante", "import os\nfrom flask import request\ndef h():\n    v = request.args['x']\n    v = 'fijo'\n    os.system('echo ' + v)\n",
      {"cmd": False}),
    C("s16-solo-compara", "import os\nfrom flask import request\ndef h():\n    if request.args.get('modo') == 'debug':\n        os.system('echo hola')\n",
      {"cmd": False}),
    C("s17-literal-eval", "import ast\nfrom flask import request\ndef h():\n    return ast.literal_eval(request.args['x'])\n",
      {"code": False}),
    C("s18-re-sub-lista-blanca", "import os, re\nfrom flask import request\ndef h():\n    v = re.sub(r'[^a-zA-Z0-9_]', '', request.args['x'])\n    os.system('echo ' + v)\n",
      {"cmd": False}),
    C("s19-lista-permitidos", "import os\nfrom flask import request\nOK = ('a', 'b')\ndef h():\n    v = request.args['x']\n    if v not in OK:\n        return 'no', 400\n    os.system('echo ' + v)\n",
      {"cmd": False}),
    C("s20-sql-sqlalchemy-bind", """
from sqlalchemy import text
from flask import request
def h(conn):
    return conn.execute(text("SELECT * FROM t WHERE n = :n"), {"n": request.args["n"]})
""", {"sql": False}),
    C("s21-redirect-relativo", "from flask import redirect, request\ndef h():\n    return redirect('/panel/' + request.args['x'])\n",
      {"redirect": False}),
    C("s22-entorno-constante", "import os\nRUTA = os.environ.get('RUTA', '/tmp')\ndef h():\n    return open('/etc/hostname').read()\n",
      {"path": False}),
    # ---------------------------------------------------------------- limitaciones conocidas
    C("l01-getattr-dinamico", """
import os, sys
from flask import request
def h():
    f = getattr(os, request.args["f"])
    f(request.args["a"])
""", {"cmd": True}, "despacho dinámico con getattr: no se sigue", limitacion=True),
    C("v31-clausura", """
import os
from flask import request
def h():
    v = request.args["c"]
    def interna():
        os.system(v)
    interna()
""", {"cmd": True}, "variables capturadas por una función anidada (se ejecuta en línea)"),
    C("v32-lambda", """
import os
from flask import request
def h():
    ejecuta = lambda c: os.system(c)
    ejecuta(request.args["c"])
""", {"cmd": True}, "lambda guardada en una variable"),
    C("s23-dict-por-clave", """
import os
from flask import request
def h():
    d = {"fijo": "ls", "malo": request.args["x"]}
    os.system(d["fijo"])
""", {"cmd": False}, "diccionario literal: cada clave se sigue por separado"),
    C("v33-hilo", """
import os, threading
from flask import request
def trabajo(c):
    os.system(c)
def h():
    threading.Thread(target=trabajo, args=(request.args["c"],)).start()
""", {"cmd": True}, "Thread(target=..., args=...)"),
    C("l06-partial", """
import os, functools
from flask import request
def h():
    functools.partial(os.system, request.args["c"])()
""", {"cmd": True}, "funciones guardadas en objetos no se siguen", limitacion=True),
    C("l07-dos-instancias", """
import os
from flask import request
class Tarea:
    def __init__(self, orden):
        self.orden = orden
    def lanzar(self):
        os.system(self.orden)
def h():
    mala = Tarea(request.args["o"])
    buena = Tarea("ls")
    buena.lanzar()
""", {"cmd": False}, "los campos se siguen por clase, no por instancia: falsa alarma", limitacion=True),
    C("l08-ida-y-vuelta-bd", """
import sqlite3
from flask import request
def guardar():
    c = sqlite3.connect("x.db")
    c.execute("INSERT INTO c VALUES (?)", (request.form["t"],))
def mostrar():
    c = sqlite3.connect("x.db")
    fila = c.execute("SELECT t FROM c").fetchone()
    return "<p>" + fila[0] + "</p>"
""", {"xss": True}, "XSS almacenado: el dato pasa por la base de datos y no se sigue", limitacion=True),
]
