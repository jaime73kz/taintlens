"""Mini-tienda corregida: mismas funciones, sin los fallos."""
import html
import json
import os
from pathlib import Path
from urllib.parse import urlparse

import requests
import yaml
from flask import Flask, abort, jsonify, redirect, request, send_file, url_for
from werkzeug.utils import secure_filename

from db import buscar_producto
from utils import comprobar_servidor

app = Flask(__name__)
app.secret_key = os.environ["TIENDA_SECRET_KEY"]       # el secreto vive fuera del código

FACTURAS = Path("/srv/tienda/facturas").resolve()
HOSTS_PERMITIDOS = {"api.ejemplo.com", "cdn.ejemplo.com"}
DESTINOS = {"inicio": "inicio", "carrito": "carrito"}


@app.route("/buscar")
def buscar():
    return jsonify(buscar_producto(request.args["q"]))


@app.route("/ping")
def ping():
    try:
        return html.escape(comprobar_servidor(request.args["host"]))
    except ValueError:
        abort(400)


@app.route("/descargar")
def descargar():
    ruta = (FACTURAS / secure_filename(request.args["archivo"])).resolve()
    if not ruta.is_relative_to(FACTURAS):
        abort(403)
    return send_file(ruta)


@app.route("/proxy")
def proxy():
    url = request.args["url"]
    if urlparse(url).hostname not in HOSTS_PERMITIDOS:
        abort(400)
    return html.escape(requests.get(url, timeout=5).text)


@app.route("/saludo")
def saludo():
    return "<h1>Hola " + html.escape(request.args.get("nombre", "")) + "</h1>"


@app.route("/ir")
def ir():
    destino = request.args["destino"]
    if destino not in DESTINOS:
        abort(400)
    return redirect(url_for(DESTINOS[destino]))


@app.route("/importar", methods=["POST"])
def importar():
    return jsonify(json.loads(request.data))


@app.route("/ajustes", methods=["POST"])
def ajustes():
    return jsonify(yaml.safe_load(request.data))


if __name__ == "__main__":
    app.run(debug=os.environ.get("DEBUG") == "1")
