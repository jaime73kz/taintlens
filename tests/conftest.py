import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from taintlens.analisis import escanear


def ids(src, **kw):
    """Conjunto de ids de regla encontrados en un programa (o en un dict de archivos)."""
    fuentes = src if isinstance(src, dict) else {"app.py": src}
    return {h.regla for h in escanear(fuentes=fuentes, **kw).hallazgos}


def clases(src, **kw):
    fuentes = src if isinstance(src, dict) else {"app.py": src}
    return {h.clase for h in escanear(fuentes=fuentes, **kw).hallazgos}


def hallazgos(src, **kw):
    fuentes = src if isinstance(src, dict) else {"app.py": src}
    return escanear(fuentes=fuentes, **kw).hallazgos


@pytest.fixture
def proyecto_tmp(tmp_path):
    """Crea archivos en una carpeta temporal: proyecto_tmp({'a.py': '...'}) -> ruta."""
    def crear(archivos: dict):
        for ruta, contenido in archivos.items():
            p = tmp_path / ruta
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(contenido, bytes):
                p.write_bytes(contenido)
            else:
                p.write_text(contenido, encoding="utf-8")
        return str(tmp_path)
    return crear
