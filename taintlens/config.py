"""Configuración: archivo TOML (taintlens.toml o [tool.taintlens] en pyproject.toml)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field

try:
    import tomllib
except ModuleNotFoundError:           # pragma: no cover  (Python < 3.11)
    tomllib = None

from .catalogo import REGLAS, TODO, Catalogo, Fuente, Sumidero
from .modelo import SEVERIDADES

TIPOS_FUENTE = {"http", "red", "llm", "argv", "stdin", "entorno", "archivo"}
CLAVES_PRINCIPALES = {"excluir", "severidad_minima", "fallar_en", "reglas_desactivadas", "fuentes_archivo",
                      "estricto", "incluir_tests", "confianza_minima", "baseline"}


class ErrorConfig(ValueError):
    pass


@dataclass
class Config:
    excluir: list = field(default_factory=list)
    severidad_minima: str = "info"
    confianza_minima: str = "baja"
    fallar_en: str = "alta"
    reglas_desactivadas: set = field(default_factory=set)
    fuentes_archivo: bool = False
    estricto: bool = False
    incluir_tests: bool = True
    baseline: str = ""
    fuentes: list = field(default_factory=list)
    sumideros: list = field(default_factory=list)
    saneadores: list = field(default_factory=list)

    def catalogo(self) -> Catalogo:
        c = Catalogo(fuentes_archivo=self.fuentes_archivo)
        for f in self.fuentes:
            c.anadir_fuente(f)
        for s in self.sumideros:
            c.anadir_sumidero(s)
        for nombre, clases in self.saneadores:
            c.anadir_saneador(nombre, clases)
        return c

    def regla_activa(self, regla_id: str, clase: str) -> bool:
        return regla_id not in self.reglas_desactivadas and clase not in self.reglas_desactivadas


def _lista_str(v, campo: str) -> list:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ErrorConfig(f"«{campo}» debe ser una lista de textos.")
    return v


def _clases(v, campo: str):
    if v == "todo":
        return "todo"
    lst = _lista_str(v, campo)
    por_id = {r.id: r.clase for r in REGLAS.values()}
    out = []
    for x in lst:
        x = por_id.get(x, x)
        if x not in TODO:
            raise ErrorConfig(f"«{campo}»: clase desconocida «{x}». Clases válidas: {', '.join(sorted(TODO))}.")
        out.append(x)
    return out


def desde_dict(d: dict) -> Config:
    if not isinstance(d, dict):
        raise ErrorConfig("La configuración debe ser una tabla TOML.")
    c = Config()
    principal = d.get("taintlens", {})
    if not isinstance(principal, dict):
        raise ErrorConfig("[taintlens] debe ser una tabla.")
    desconocidas = set(principal) - CLAVES_PRINCIPALES
    if desconocidas:
        raise ErrorConfig(f"Opciones desconocidas en [taintlens]: {', '.join(sorted(desconocidas))}.")
    if "excluir" in principal:
        c.excluir = _lista_str(principal["excluir"], "excluir")
    for campo in ("severidad_minima", "fallar_en"):
        if campo in principal:
            v = principal[campo]
            if v not in SEVERIDADES and not (campo == "fallar_en" and v == "nunca"):
                raise ErrorConfig(f"«{campo}» debe ser uno de: {', '.join(SEVERIDADES)}"
                                  f"{' o nunca' if campo == 'fallar_en' else ''}.")
            setattr(c, campo, v)
    if "confianza_minima" in principal:
        if principal["confianza_minima"] not in ("baja", "media", "alta"):
            raise ErrorConfig("«confianza_minima» debe ser baja, media o alta.")
        c.confianza_minima = principal["confianza_minima"]
    if "reglas_desactivadas" in principal:
        c.reglas_desactivadas = set(_lista_str(principal["reglas_desactivadas"], "reglas_desactivadas"))
    for campo in ("fuentes_archivo", "estricto", "incluir_tests"):
        if campo in principal:
            if not isinstance(principal[campo], bool):
                raise ErrorConfig(f"«{campo}» debe ser true o false.")
            setattr(c, campo, principal[campo])
    if "baseline" in principal:
        if not isinstance(principal["baseline"], str):
            raise ErrorConfig("«baseline» debe ser un texto con la ruta del archivo.")
        c.baseline = principal["baseline"]

    for i, f in enumerate(d.get("fuente", []), 1):
        tipo, nombre = f.get("tipo"), f.get("nombre")
        if tipo not in TIPOS_FUENTE:
            raise ErrorConfig(f"[[fuente]] #{i}: «tipo» debe ser uno de {', '.join(sorted(TIPOS_FUENTE))}.")
        if not isinstance(nombre, str) or not nombre:
            raise ErrorConfig(f"[[fuente]] #{i}: falta «nombre».")
        modo = f.get("modo", "llamada")
        if modo not in ("llamada", "objeto"):
            raise ErrorConfig(f"[[fuente]] #{i}: «modo» debe ser llamada u objeto.")
        c.fuentes.append(Fuente(tipo, (nombre,), modo=modo))
    for i, s in enumerate(d.get("sumidero", []), 1):
        clase, nombre = s.get("clase"), s.get("nombre")
        por_id = {r.id: r.clase for r in REGLAS.values()}
        clase = por_id.get(clase, clase)
        if clase not in TODO:
            raise ErrorConfig(f"[[sumidero]] #{i}: «clase» desconocida. Válidas: {', '.join(sorted(TODO))}.")
        if not isinstance(nombre, str) or not nombre:
            raise ErrorConfig(f"[[sumidero]] #{i}: falta «nombre».")
        args = s.get("args", [0])
        if not isinstance(args, list) or not all(isinstance(a, int) and a >= 0 for a in args):
            raise ErrorConfig(f"[[sumidero]] #{i}: «args» debe ser una lista de posiciones (0, 1, ...).")
        kws = tuple(_lista_str(s.get("kws", []), "kws"))
        c.sumideros.append(Sumidero(clase, (nombre,), args=tuple(args), kws=kws,
                                    etiqueta=s.get("etiqueta", "sumidero personalizado")))
    for i, s in enumerate(d.get("saneador", []), 1):
        nombre = s.get("nombre")
        if not isinstance(nombre, str) or not nombre:
            raise ErrorConfig(f"[[saneador]] #{i}: falta «nombre».")
        clases = _clases(s.get("clases", "todo"), f"[[saneador]] #{i} clases")
        c.saneadores.append((nombre, clases))
    return c


def cargar(ruta: str | None, buscar_desde: str = ".") -> Config:
    """Carga la configuración indicada o busca taintlens.toml / pyproject.toml."""
    if tomllib is None:
        if ruta:
            raise ErrorConfig("Leer TOML necesita Python 3.11 o superior.")
        return Config()
    candidatos = [ruta] if ruta else [os.path.join(buscar_desde, "taintlens.toml"),
                                      os.path.join(buscar_desde, "pyproject.toml")]
    for cand in candidatos:
        if cand and os.path.isfile(cand):
            try:
                with open(cand, "rb") as f:
                    datos = tomllib.load(f)
            except tomllib.TOMLDecodeError as e:
                raise ErrorConfig(f"{cand}: TOML no válido ({e}).") from None
            except OSError as e:
                raise ErrorConfig(f"{cand}: no se pudo leer ({e.__class__.__name__}).") from None
            if cand.endswith("pyproject.toml"):
                herramienta = datos.get("tool", {}).get("taintlens")
                if herramienta is None:
                    continue
                datos = {"taintlens": {k: v for k, v in herramienta.items()
                                       if k not in ("fuente", "sumidero", "saneador")},
                         **{k: herramienta[k] for k in ("fuente", "sumidero", "saneador") if k in herramienta}}
            return desde_dict(datos)
        elif ruta:
            raise ErrorConfig(f"No existe el archivo de configuración «{ruta}».")
    return Config()
