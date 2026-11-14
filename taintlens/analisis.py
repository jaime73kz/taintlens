"""Punto de entrada de la biblioteca: `escanear()` junta todo el análisis."""
from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass, field

from . import reglas_ast, supresion
from .config import Config
from .modelo import ORDEN_SEV
from .motor import Motor
from .proyecto import Proyecto

ORDEN_CONF = {"baja": 0, "media": 1, "alta": 2}


@dataclass
class Resultado:
    hallazgos: list = field(default_factory=list)
    suprimidos: list = field(default_factory=list)
    en_baseline: int = 0
    errores: list = field(default_factory=list)
    omitidos: list = field(default_factory=list)
    limites: list = field(default_factory=list)
    archivos: int = 0
    lineas: int = 0
    funciones: int = 0
    entradas: int = 0
    rondas: int = 0
    segundos: float = 0.0

    def por_severidad(self) -> dict:
        r = {s: 0 for s in ("critica", "alta", "media", "baja", "info")}
        for h in self.hallazgos:
            r[h.severidad] += 1
        return r

    def peor(self) -> str | None:
        return max((h.severidad for h in self.hallazgos), key=lambda s: ORDEN_SEV[s], default=None)


def _en_hilo_grande(fn):
    """Ejecuta fn con una pila grande: el código muy anidado no debe tumbar el análisis."""
    resultado: dict = {}

    def objetivo():
        try:
            resultado["v"] = fn()
        except BaseException as e:               # noqa: BLE001
            resultado["e"] = e

    limite = sys.getrecursionlimit()
    tam = None
    try:
        tam = threading.stack_size(256 * 1024 * 1024)
    except (ValueError, RuntimeError):
        try:
            tam = threading.stack_size(64 * 1024 * 1024)
        except (ValueError, RuntimeError):
            tam = None
    sys.setrecursionlimit(max(limite, 12000))
    try:
        t = threading.Thread(target=objetivo)
        try:
            t.start()
        except RuntimeError:                     # el sistema no deja reservar tanta pila: se usa la actual
            if tam is not None:
                threading.stack_size(tam)
            objetivo()
        else:
            t.join()
    finally:
        sys.setrecursionlimit(limite)
        if tam is not None:
            threading.stack_size(tam)
    if "e" in resultado:
        raise resultado["e"]
    return resultado["v"]


def reglas_ast_clases():
    from .catalogo import SIN_FLUJO
    return SIN_FLUJO


def _depurar(hs: list) -> list:
    """Quita avisos genéricos cuando ya hay uno más específico en la misma línea."""
    en = {(h.ruta, h.linea): set() for h in hs}
    for h in hs:
        en[(h.ruta, h.linea)].add(h.regla)
    out = []
    vistos = set()
    for h in hs:
        # TL206/TL210 ya los cubre TL107; TL207 ya lo cubre TL101/TL102
        reglas = en[(h.ruta, h.linea)]
        if h.clase in reglas_ast_clases():
            k = (h.regla, h.ruta, h.linea)
            if k in vistos:
                continue
            vistos.add(k)
        if h.regla in ("TL206", "TL210") and "TL107" in reglas:
            continue
        if h.regla == "TL207" and ({"TL101", "TL102"} & reglas):
            continue
        out.append(h)
    return out


def escanear(rutas=None, config: Config | None = None, fuentes: dict | None = None,
             baseline: set | None = None) -> Resultado:
    """Analiza rutas (archivos o carpetas) o un diccionario {ruta: código}."""
    return _en_hilo_grande(lambda: _escanear(rutas, config, fuentes, baseline))


def _escanear(rutas, config, fuentes, baseline) -> Resultado:
    inicio = time.perf_counter()
    config = config or Config()
    if fuentes is not None:
        proyecto = Proyecto.desde_fuentes(fuentes)
    else:
        proyecto = Proyecto.cargar(rutas or ["."], excluir=config.excluir, incluir_tests=config.incluir_tests)
    catalogo = config.catalogo()
    motor = Motor(proyecto, catalogo)
    motor.estricto = config.estricto
    flujo = motor.analizar()
    todos = _depurar(flujo + reglas_ast.analizar(proyecto))
    todos = [h for h in todos if config.regla_activa(h.regla, h.clase)
             and ORDEN_SEV[h.severidad] >= ORDEN_SEV[config.severidad_minima]
             and ORDEN_CONF[h.confianza] >= ORDEN_CONF[config.confianza_minima]]
    visibles, suprimidos = supresion.aplicar_comentarios(todos, proyecto)
    en_base = 0
    if baseline:
        visibles, en_base = supresion.filtrar_baseline(visibles, baseline)
    visibles.sort(key=lambda h: (-ORDEN_SEV[h.severidad], h.ruta, h.linea, h.regla))
    r = Resultado(visibles, suprimidos, en_base, list(proyecto.errores), list(proyecto.omitidos),
                  list(motor.limites_alcanzados), len(proyecto.modulos), proyecto.total_lineas(),
                  len(proyecto.funcs), len(motor.entradas), motor.rondas,
                  round(time.perf_counter() - inicio, 3))
    return r
