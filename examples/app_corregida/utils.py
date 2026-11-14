"""Versión corregida: lista de argumentos, validación estricta."""
import re
import subprocess

HOST_VALIDO = re.compile(r"[A-Za-z0-9.-]{1,253}")


def comprobar_servidor(host):
    if not HOST_VALIDO.fullmatch(host):
        raise ValueError("host no válido")
    return subprocess.run(["ping", "-c", "1", "--", host], capture_output=True, text=True, timeout=10).stdout
