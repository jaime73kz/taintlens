"""Funciones auxiliares de la mini-tienda (con fallos a propósito, para practicar)."""
import subprocess


def comprobar_servidor(host):
    # El comando se construye con texto: quien controle «host» controla el comando.
    return subprocess.run("ping -c 1 " + host, shell=True, capture_output=True, text=True).stdout
