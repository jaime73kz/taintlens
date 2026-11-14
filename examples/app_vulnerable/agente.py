"""Un agente con herramientas. Dos formas típicas de fallar con modelos de lenguaje."""
import subprocess

from mcp.server.fastmcp import FastMCP
from openai import OpenAI

mcp = FastMCP("asistente")
cliente = OpenAI()


@mcp.tool()
def ejecutar_comando(comando: str) -> str:
    """El modelo elige «comando»: cualquier cosa que se le cuele en el prompt acaba en el shell."""
    return subprocess.run(comando, shell=True, capture_output=True, text=True).stdout


def resolver_con_python(pregunta: str):
    respuesta = cliente.chat.completions.create(
        model="gpt-4o-mini", messages=[{"role": "user", "content": "Escribe código Python para: " + pregunta}])
    codigo = respuesta.choices[0].message.content
    exec(codigo)                                                           # el código lo escribe el modelo


def resumir_pagina(url: str):
    import requests
    pagina = requests.get(url, timeout=5).text
    return cliente.chat.completions.create(
        model="gpt-4o-mini", messages=[{"role": "user", "content": "Resume esto: " + pagina}])   # inyección de instrucciones
