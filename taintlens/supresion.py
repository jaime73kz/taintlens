"""Silenciar hallazgos: comentarios en el código y archivo de referencia (baseline)."""
from __future__ import annotations

import json
import os
import re

from .modelo import Hallazgo

RX_IGNORAR = re.compile(r"#\s*taintlens:\s*ignore(?:\[([A-Za-z0-9_,\s]+)\])?", re.I)
RX_ARCHIVO = re.compile(r"#\s*taintlens:\s*ignore-file", re.I)
RX_NOSEC = re.compile(r"#\s*nosec\b", re.I)


def _reglas(grupo: str | None):
    if grupo is None:
        return None
    return {x.strip().upper() for x in grupo.split(",") if x.strip()}


def aplicar_comentarios(hallazgos, proyecto, respetar_nosec: bool = True):
    """Devuelve (visibles, suprimidos)."""
    por_ruta = {m.ruta: m for m in proyecto.modulos.values()}
    visibles, suprimidos = [], []
    cache_archivo: dict = {}
    for h in hallazgos:
        m = por_ruta.get(h.ruta)
        if m is None:
            visibles.append(h)
            continue
        if h.ruta not in cache_archivo:
            cache_archivo[h.ruta] = any(RX_ARCHIVO.search(l) for l in m.lineas[:15])
        if cache_archivo[h.ruta] or _silenciado(h, m.lineas, respetar_nosec):
            suprimidos.append(h)
        else:
            visibles.append(h)
    return visibles, suprimidos


def _silenciado(h: Hallazgo, lineas, respetar_nosec: bool) -> bool:
    candidatas = [h.linea]
    # una línea de comentario justo encima también vale
    if h.linea >= 2 and lineas[h.linea - 2].strip().startswith("#"):
        candidatas.append(h.linea - 1)
    # el sumidero puede ocupar varias líneas: miramos hasta 3 más
    candidatas.extend(range(h.linea + 1, min(len(lineas), h.linea + 3) + 1))
    for ln in candidatas:
        if not (0 < ln <= len(lineas)):
            continue
        txt = lineas[ln - 1]
        mt = RX_IGNORAR.search(txt)
        if mt and not RX_ARCHIVO.search(txt):
            reglas = _reglas(mt.group(1))
            if reglas is None or h.regla.upper() in reglas or h.clase.upper() in reglas:
                if ln == h.linea or txt.strip().startswith("#") or ln > h.linea:
                    return True
        if respetar_nosec and ln == h.linea and RX_NOSEC.search(txt):
            return True
    return False


# ----------------------------------------------------------------------
def guardar_baseline(ruta: str, hallazgos) -> int:
    datos = {"version": 1, "huellas": sorted({h.huella for h in hallazgos})}
    with open(ruta, "w", encoding="utf-8") as f:
        json.dump(datos, f, indent=2)
        f.write("\n")
    return len(datos["huellas"])


def cargar_baseline(ruta: str) -> set:
    if not os.path.isfile(ruta):
        raise FileNotFoundError(f"No existe el archivo de referencia «{ruta}».")
    try:
        with open(ruta, encoding="utf-8") as f:
            d = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"«{ruta}» no es un JSON válido: {e.msg}.") from None
    if not isinstance(d, dict) or not isinstance(d.get("huellas"), list):
        raise ValueError(f"«{ruta}» no tiene el formato de un archivo de referencia de TaintLens.")
    return {str(x) for x in d["huellas"]}


def filtrar_baseline(hallazgos, huellas: set):
    nuevos = [h for h in hallazgos if h.huella not in huellas]
    return nuevos, len(hallazgos) - len(nuevos)
