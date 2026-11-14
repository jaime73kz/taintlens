"""Carga de archivos y índice del proyecto: módulos, funciones, clases e imports."""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field

EXCLUIR_POR_DEFECTO = (".git", ".hg", ".svn", ".venv", "venv", "env", ".env", "node_modules", "__pycache__",
                       "build", "dist", "site-packages", ".tox", ".mypy_cache", ".pytest_cache", ".eggs",
                       ".ruff_cache", "migrations")
MAX_BYTES = 2_000_000


@dataclass
class FuncInfo:
    id: str
    modulo: str
    qual: str
    nodo: ast.AST
    clase: str | None            # id de la clase si es método
    params: list
    vararg: str | None
    kwarg: str | None
    estatico: bool
    es_classmethod: bool
    decoradores: list
    anotaciones: dict

    @property
    def nombre(self) -> str:
        return self.qual.rsplit(".", 1)[-1]

    def indice_vararg(self) -> int:
        return len(self.params)

    def indice_kwarg(self) -> int:
        return len(self.params) + 1


@dataclass
class ClaseInfo:
    id: str
    modulo: str
    nombre: str
    nodo: ast.ClassDef
    bases: list = field(default_factory=list)       # nombres cualificados sin resolver
    metodos: dict = field(default_factory=dict)     # nombre -> FuncInfo
    campos_anotados: list = field(default_factory=list)
    es_dataclass: bool = False


@dataclass
class Modulo:
    nombre: str
    ruta: str
    arbol: ast.Module
    lineas: list
    imports: dict
    es_init: bool = False


class Proyecto:
    def __init__(self):
        self.modulos: dict[str, Modulo] = {}
        self.funcs: dict[str, FuncInfo] = {}
        self.clases: dict[str, ClaseInfo] = {}
        self.por_metodo: dict[str, list] = {}
        self.errores: list[tuple[str, str]] = []
        self.omitidos: list[tuple[str, str]] = []
        self._por_sufijo: dict[str, list] = {}

    # ------------------------------------------------------------------
    @classmethod
    def cargar(cls, rutas, excluir=(), incluir_tests: bool = True) -> "Proyecto":
        p = cls()
        excl = set(EXCLUIR_POR_DEFECTO) | set(excluir)
        for ruta in rutas:
            ruta = os.path.normpath(ruta)
            if os.path.isfile(ruta):
                p._anadir_archivo(ruta, os.path.dirname(ruta) or ".", prefijo="")
            elif os.path.isdir(ruta):
                prefijo = os.path.basename(os.path.abspath(ruta)) if os.path.exists(
                    os.path.join(ruta, "__init__.py")) else ""
                for raiz, dirs, archivos in os.walk(ruta):
                    dirs[:] = sorted(d for d in dirs if d not in excl and not d.endswith(".egg-info")
                                     and (incluir_tests or d not in ("tests", "test")))
                    for a in sorted(archivos):
                        if a.endswith(".py"):
                            p._anadir_archivo(os.path.join(raiz, a), ruta, prefijo)
            else:
                p.errores.append((ruta, "no existe"))
        p._indexar()
        return p

    @classmethod
    def desde_fuentes(cls, fuentes: dict) -> "Proyecto":
        """Construye un proyecto en memoria: {'pkg/mod.py': 'codigo'}."""
        p = cls()
        for ruta, codigo in fuentes.items():
            p._anadir_texto(ruta, codigo, _nombre_modulo(ruta, "", ""))
        p._indexar()
        return p

    def _anadir_archivo(self, ruta: str, base: str, prefijo: str) -> None:
        try:
            if os.path.getsize(ruta) > MAX_BYTES:
                self.omitidos.append((ruta, "archivo demasiado grande"))
                return
            with open(ruta, "rb") as f:
                datos = f.read()
        except OSError as e:
            self.errores.append((ruta, f"no se pudo leer: {e.__class__.__name__}"))
            return
        if b"\x00" in datos[:4096]:
            self.omitidos.append((ruta, "archivo binario"))
            return
        texto = datos.decode("utf-8", errors="replace")
        self._anadir_texto(ruta, texto, _nombre_modulo(ruta, base, prefijo))

    def _anadir_texto(self, ruta: str, texto: str, nombre: str) -> None:
        try:
            arbol = ast.parse(texto.lstrip("﻿"), filename=ruta)
        except SyntaxError as e:
            self.errores.append((ruta, f"error de sintaxis en la línea {e.lineno}"))
            return
        except (ValueError, RecursionError, MemoryError, OverflowError) as e:
            self.errores.append((ruta, f"no se pudo analizar ({e.__class__.__name__})"))
            return
        ruta = _relativa(ruta)
        base = nombre
        k = 2
        while nombre in self.modulos:        # nombres repetidos (p. ej. dos main.py sueltos)
            nombre = f"{base}~{k}"
            k += 1
        m = Modulo(nombre, ruta, arbol, texto.splitlines(), {}, os.path.basename(ruta) == "__init__.py")
        self.modulos[nombre] = m

    # ------------------------------------------------------------------
    def _indexar(self) -> None:
        for nombre, m in self.modulos.items():
            m.imports = _imports(m)
            partes = nombre.split(".")
            for k in range(len(partes)):
                self._por_sufijo.setdefault(".".join(partes[k:]), []).append(nombre)
            _Indexador(self, m).visit(m.arbol)
        for f in self.funcs.values():
            if f.clase:
                self.por_metodo.setdefault(f.nombre, []).append(f)

    def buscar_modulo(self, nombre: str) -> Modulo | None:
        if nombre in self.modulos:
            return self.modulos[nombre]
        c = self._por_sufijo.get(nombre)
        if c and len(set(c)) == 1:
            return self.modulos[c[0]]
        return None

    def buscar_clase(self, modulo: str, nombre: str) -> ClaseInfo | None:
        return self.clases.get(f"{modulo}:{nombre}")

    def mro(self, cid: str, _vistos=None) -> list[ClaseInfo]:
        """Clase y sus bases del proyecto (en profundidad, sin repeticiones)."""
        vistos = _vistos if _vistos is not None else set()
        c = self.clases.get(cid)
        if c is None or cid in vistos:
            return []
        vistos.add(cid)
        r = [c]
        m = self.modulos[c.modulo]
        for b in c.bases:
            r.extend(self.mro_de_nombre(m, b, vistos))
        return r

    def mro_de_nombre(self, m: Modulo, nombre: str, vistos) -> list[ClaseInfo]:
        ci = self.resolver_clase(m, nombre)
        return self.mro(ci.id, vistos) if ci else []

    def resolver_clase(self, m: Modulo, nombre: str) -> ClaseInfo | None:
        """Resuelve un nombre (ya cualificado por imports si procede) a una clase del proyecto."""
        c = self.clases.get(f"{m.nombre}:{nombre}")
        if c:
            return c
        qn = m.imports.get(nombre.split(".")[0])
        if qn:
            nombre = qn + nombre[len(nombre.split(".")[0]):]
        partes = nombre.split(".")
        for k in range(len(partes) - 1, 0, -1):
            mod = self.buscar_modulo(".".join(partes[:k]))
            if mod:
                c = self.clases.get(f"{mod.nombre}:{'.'.join(partes[k:])}")
                if c:
                    return c
        return None

    def metodo(self, cid: str, nombre: str) -> FuncInfo | None:
        for c in self.mro(cid):
            f = c.metodos.get(nombre)
            if f:
                return f
        return None

    def total_lineas(self) -> int:
        return sum(len(m.lineas) for m in self.modulos.values())


# ----------------------------------------------------------------------
def _relativa(ruta: str) -> str:
    """Ruta con «/» y relativa a la carpeta actual cuando está dentro de ella."""
    try:
        rel = os.path.relpath(ruta)
        if not rel.startswith(".."):
            ruta = rel
    except ValueError:
        pass
    return ruta.replace("\\", "/")


def _nombre_modulo(ruta: str, base: str, prefijo: str) -> str:
    rel = os.path.relpath(ruta, base) if base else ruta
    rel = rel.replace("\\", "/")
    if rel.startswith("./"):
        rel = rel[2:]
    partes = [x for x in rel[:-3].split("/") if x and x != ".."]
    if partes and partes[-1] == "__init__":
        partes = partes[:-1]
    if prefijo:
        partes = [prefijo] + partes
    return ".".join(partes) or "__main__"


def _imports(m: Modulo) -> dict:
    """alias -> nombre cualificado, solo de los imports del nivel superior."""
    r: dict = {}
    pkg = m.nombre.split(".")
    if not m.es_init:
        pkg = pkg[:-1]
    for n in ast.walk(m.arbol):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.asname:
                    r[a.asname] = a.name
                else:
                    r[a.name.split(".")[0]] = a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom):
            if n.level:
                base = pkg[: max(0, len(pkg) - (n.level - 1))]
                modulo = ".".join(base + ([n.module] if n.module else []))
            else:
                modulo = n.module or ""
            for a in n.names:
                if a.name == "*":
                    continue
                r[a.asname or a.name] = f"{modulo}.{a.name}" if modulo else a.name
    return r


def imports_de(nodo, base: dict) -> dict:
    """Imports de un cuerpo de función, añadidos a los del módulo."""
    r = dict(base)
    for n in ast.walk(nodo):
        if isinstance(n, ast.Import):
            for a in n.names:
                if a.asname:
                    r[a.asname] = a.name
                else:
                    r[a.name.split(".")[0]] = a.name.split(".")[0]
        elif isinstance(n, ast.ImportFrom) and not n.level:
            for a in n.names:
                if a.name != "*":
                    r[a.asname or a.name] = f"{n.module}.{a.name}" if n.module else a.name
    return r


def _nombre_deco(d) -> str:
    d = d.func if isinstance(d, ast.Call) else d
    partes = []
    while isinstance(d, ast.Attribute):
        partes.append(d.attr)
        d = d.value
    if isinstance(d, ast.Name):
        partes.append(d.id)
    return ".".join(reversed(partes))


class _Indexador(ast.NodeVisitor):
    def __init__(self, p: Proyecto, m: Modulo):
        self.p, self.m = p, m
        self.pila: list[str] = []
        self.clase_actual: str | None = None

    def visit_ClassDef(self, n: ast.ClassDef):
        qual = ".".join(self.pila + [n.name])
        cid = f"{self.m.nombre}:{qual}"
        c = ClaseInfo(cid, self.m.nombre, qual, n)
        for b in n.bases:
            nb = _nombre_deco(b)
            if nb:
                c.bases.append(nb)
        c.es_dataclass = any(_nombre_deco(d).split(".")[-1] in ("dataclass", "define", "attrs", "s")
                             for d in n.decorator_list) or any(
            b.split(".")[-1] in ("NamedTuple", "BaseModel", "TypedDict") for b in c.bases)
        for s in n.body:
            if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name):
                c.campos_anotados.append(s.target.id)
        self.p.clases[cid] = c
        anterior = self.clase_actual
        self.clase_actual = cid
        self.pila.append(n.name)
        for s in n.body:
            self.visit(s)
        self.pila.pop()
        self.clase_actual = anterior

    def _func(self, n):
        qual = ".".join(self.pila + [n.name])
        fid = f"{self.m.nombre}:{qual}"
        a = n.args
        params = [x.arg for x in a.posonlyargs + a.args + a.kwonlyargs]
        decos = [_nombre_deco(d) for d in n.decorator_list]
        estatico = "staticmethod" in decos
        clase = self.clase_actual if self.pila and self.clase_actual and \
            self.pila[-1] == self.p.clases[self.clase_actual].nombre.split(".")[-1] else None
        anot = {}
        for x in a.posonlyargs + a.args + a.kwonlyargs:
            if x.annotation is not None:
                an = _nombre_deco(x.annotation) if isinstance(x.annotation, (ast.Name, ast.Attribute)) else ""
                if not an and isinstance(x.annotation, ast.Constant) and isinstance(x.annotation.value, str):
                    an = x.annotation.value
                if an:
                    anot[x.arg] = an
        f = FuncInfo(fid, self.m.nombre, qual, n, clase, params, a.vararg.arg if a.vararg else None,
                     a.kwarg.arg if a.kwarg else None, estatico, "classmethod" in decos,
                     list(n.decorator_list), anot)
        self.p.funcs[fid] = f
        if clase:
            self.p.clases[clase].metodos[n.name] = f
        anterior = self.clase_actual
        self.clase_actual = None
        self.pila.append(n.name)
        for s in n.body:
            self.visit(s)
        self.pila.pop()
        self.clase_actual = anterior

    visit_FunctionDef = _func
    visit_AsyncFunctionDef = _func

    def generic_visit(self, n):
        """Solo baja por sentencias (cuerpos): las expresiones no definen funciones ni clases."""
        for campo in ("body", "orelse", "finalbody", "handlers", "cases"):
            for s in getattr(n, campo, None) or []:
                if isinstance(s, ast.AST):
                    self.visit(s)
