"""Mini-tienda con fallos a propósito. NO la uses en producción: sirve para probar TaintLens."""
import pickle
import requests
import yaml
from flask import Flask, redirect, render_template_string, request, send_file

from db import buscar_producto
from utils import comprobar_servidor

app = Flask(__name__)
app.secret_key = "clave-super-secreta-12345"          # secreto escrito en el código


@app.route("/buscar")
def buscar():
    return str(buscar_producto(request.args["q"]))     # SQL: el dato cruza db.py


@app.route("/ping")
def ping():
    return comprobar_servidor(request.args["host"])    # comando: el dato cruza utils.py


@app.route("/descargar")
def descargar():
    return send_file("/srv/tienda/facturas/" + request.args["archivo"])   # ../../etc/passwd


@app.route("/proxy")
def proxy():
    return requests.get(request.args["url"], timeout=5).text              # SSRF


@app.route("/saludo")
def saludo():
    return "<h1>Hola " + request.args.get("nombre", "") + "</h1>"          # XSS


@app.route("/ir")
def ir():
    return redirect(request.args["destino"])                               # redirección abierta


@app.route("/importar", methods=["POST"])
def importar():
    pedido = pickle.loads(request.data)                                    # deserialización
    return str(pedido)


@app.route("/ajustes", methods=["POST"])
def ajustes():
    return str(yaml.load(request.data))                                    # yaml sin cargador seguro


@app.route("/plantilla")
def plantilla():
    return render_template_string(request.args["t"])                       # SSTI


if __name__ == "__main__":
    app.run(debug=True)                                                    # modo depuración
