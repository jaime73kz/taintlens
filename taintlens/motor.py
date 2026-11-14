"""Motor de análisis de flujo de datos (taint analysis) interprocedural.

Cada función se analiza con parámetros simbólicos («param:N») para obtener un
*resumen*: qué devuelve, a qué sumideros llegan sus parámetros y qué campos de
objeto escribe. Los resúmenes se recalculan por rondas hasta que no cambian
(punto fijo). Después una pasada final con informes produce los hallazgos,
sustituyendo los símbolos por los datos reales de cada llamada.
"""
from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, field, replace

from .catalogo import (Catalogo, LIMPIAN_TODO, METODOS_COMUNES, METODOS_LIMPIOS, METODOS_MUTADORES,
                       PROPAGA_CONOCIDOS, REGLAS, TODO, DECORADORES_ENTRADA)
from .modelo import (Hallazgo, ORIGENES_LOCALES, Paso, Taint, Taints, VACIO, bajar)
from .proyecto import FuncInfo, Modulo, Proyecto, imports_de

MAX_RONDAS = 6
CLASES_LOCALES = frozenset({"cmd", "code", "deser"})
# Lo que descarga el propio programa no lo elige un atacante: solo importa si acaba ejecutándose o interpretándose.
CLASES_RED = frozenset({"cmd", "code", "sql", "deser", "xxe", "ssti", "llm_prompt", "xss"})
ETIQUETA_ORIGEN = {
    "http": "entrada HTTP", "red": "datos recibidos por red", "llm": "texto o argumento generado por un modelo",
    "argv": "argumento de línea de comandos", "stdin": "entrada estándar", "entorno": "variable de entorno",
    "archivo": "contenido de un archivo",
}
SEGURAS_YAML = {"SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader"}
TERMINADORES = {"abort", "exit", "quit", "_exit"}


def _src(n, limite: int = 70) -> str:
    try:
        s = ast.unparse(n)
    except Exception:
        return "?"
    s = " ".join(s.split())
    return s if len(s) <= limite else s[: limite - 1] + "…"


def descomponer(n):
    attrs = []
    while isinstance(n, ast.Attribute):
        attrs.append(n.attr)
        n = n.value
    attrs.reverse()
    if isinstance(n, ast.Name):
        return n.id, attrs, n
    return None, attrs, n


@dataclass(frozen=True)
class SumParam:
    param: int
    clase: str
    etiqueta: str
    confianza: str
    pasos: tuple            # recorrido dentro de la función hasta el sumidero (el último es el sumidero)


@dataclass
class Resumen:
    retorno: Taints = VACIO
    sumideros: dict = field(default_factory=dict)
    campos: dict = field(default_factory=dict)

    def firma(self):
        return (hash(self.retorno.claves()), hash(frozenset(self.sumideros)),
                hash(frozenset((k, v.claves()) for k, v in self.campos.items())))


class Motor:
    def __init__(self, proyecto: Proyecto, catalogo: Catalogo, explicito_tipos_local: bool = False):
        self.p = proyecto
        self.cat = catalogo
        self.resumenes: dict[str, Resumen] = {}
        self.campos: dict[tuple, Taints] = {}
        self.campo_tipos: dict[tuple, str] = {}
        self.globales: dict[str, dict] = {m: {} for m in proyecto.modulos}
        self.globales_tipos: dict[str, dict] = {m: {} for m in proyecto.modulos}
        self.hallazgos: dict[tuple, Hallazgo] = {}
        self.reportar = False
        self.estricto = False
        self.limites_alcanzados: list[str] = []
        self.rondas = 0
        self.entradas: list[tuple[str, str]] = []
        self._es_flask: dict[str, bool] = {}
        self._alcance: dict[str, set] = {}

    # ------------------------------------------------------------------
    def analizar(self) -> list[Hallazgo]:
        antes = None
        for r in range(MAX_RONDAS):
            self.rondas = r + 1
            self._pasada()
            ahora = self._firma()
            if ahora == antes:
                break
            antes = ahora
        self.reportar = True
        self._pasada()
        return list(self.hallazgos.values())

    def _firma(self):
        return (tuple(sorted((k, r.firma()) for k, r in self.resumenes.items())),
                hash(frozenset((k, v.claves()) for k, v in self.campos.items())),
                hash(frozenset((m, tuple(sorted((n, hash(t.claves())) for n, t in g.items())))
                               for m, g in self.globales.items())))

    def _pasada(self) -> None:
        for nombre in sorted(self.p.modulos):
            self._analizar_modulo(self.p.modulos[nombre])
        for fid in sorted(self.p.funcs):
            f = self.p.funcs[fid]
            self._analizar_funcion(f, real=False)
        for fid in sorted(self.p.funcs):
            f = self.p.funcs[fid]
            ent = self._entrada(f)
            if ent:
                if self.reportar:
                    self.entradas.append((fid, ent[0]))
                self._analizar_funcion(f, real=True, entrada=ent)

    def _analizar_modulo(self, m: Modulo) -> None:
        a = _Analisis(self, m, None)
        a.env = self.globales[m.nombre]
        a.tipos = self.globales_tipos[m.nombre]
        a.modo_modulo = True
        a.ejecutar(m.arbol.body, a.env)

    def _analizar_funcion(self, f: FuncInfo, real: bool, entrada=None) -> None:
        m = self.p.modulos[f.modulo]
        a = _Analisis(self, m, f)
        a.preparar_parametros(real, entrada)
        try:
            a.ejecutar(f.nodo.body, a.env)
        except RecursionError:
            self.limites_alcanzados.append(f"{m.ruta}:{f.qual}: anidamiento demasiado profundo")
            return
        if not real:
            self.resumenes[f.id] = Resumen(a.retorno, a.sumideros, a.campos_resumen)

    # ------------------------------------------------------------------
    def _entrada(self, f: FuncInfo):
        """(tipo, indices de parámetros contaminados) si la función es un punto de entrada."""
        m = self.p.modulos[f.modulo]
        for d in f.decoradores:
            nodo = d.func if isinstance(d, ast.Call) else d
            base, attrs, _ = descomponer(nodo)
            nombre = attrs[-1] if attrs else base
            if nombre not in DECORADORES_ENTRADA:
                continue
            if nombre in ("get", "post", "put", "delete", "patch", "head", "options") and not isinstance(d, ast.Call):
                continue
            if nombre in ("get", "post", "put", "delete", "patch", "head", "options") and not attrs:
                continue
            return DECORADORES_ENTRADA[nombre], "todos"
        if f.qual == "lambda_handler" or (f.nombre == "handler" and f.params[:2] == ["event", "context"]):
            return "http", (0,)
        if f.params and f.params[0] == "request" and any(
                v.split(".")[0] == "django" for v in m.imports.values()):
            return "http", (0,)
        return None

    def alcance(self, m: Modulo) -> set:
        """Módulos que `m` puede estar usando: él mismo y los que importa."""
        r = self._alcance.get(m.nombre)
        if r is None:
            r = {m.nombre}
            for qn in m.imports.values():
                partes = qn.split(".")
                for k in range(len(partes), 0, -1):
                    mod = self.p.buscar_modulo(".".join(partes[:k]))
                    if mod:
                        r.add(mod.nombre)
                        break
            self._alcance[m.nombre] = r
        return r

    def es_flask(self, modulo: str) -> bool:
        if modulo not in self._es_flask:
            m = self.p.modulos[modulo]
            self._es_flask[modulo] = any(v.split(".")[0] in ("flask", "bottle", "quart")
                                         for v in m.imports.values())
        return self._es_flask[modulo]

    # ------------------------------------------------------------------
    def registrar(self, h: Hallazgo) -> None:
        clave = (h.clase, h.ruta, h.linea, h.col, h.traza[0].ruta, h.traza[0].linea)
        previo = self.hallazgos.get(clave)
        if previo is None or len(h.traza) < len(previo.traza):
            self.hallazgos[clave] = h


# ======================================================================

class _Analisis:
    """Análisis de un cuerpo (función o módulo) con su entorno."""

    def __init__(self, motor: Motor, m: Modulo, f: FuncInfo | None):
        self.mo = motor
        self.m = m
        self.f = f
        self.cat = motor.cat
        self.p = motor.p
        self.env: dict = {}
        self.tipos: dict = {}
        self.retorno = VACIO
        self.sumideros: dict = {}
        self.campos_resumen: dict = {}
        self.modo_modulo = False
        self.imps = imports_de(f.nodo, m.imports) if f else m.imports
        self.globales_decl: set = set()
        self.funcs_locales: dict = {}
        self.defs_locales: dict = {}
        self.lambdas: dict = {}
        self._inline: set = set()
        self.entrada_tipo: str | None = None
        self.clase_id = f.clase if f else None
        self.lineas = m.lineas

    # ------------------------------------------------------------------ utilidades
    def paso(self, n, texto: str) -> Paso:
        ln = getattr(n, "lineno", 1)
        cod = self.lineas[ln - 1].strip()[:160] if 0 < ln <= len(self.lineas) else ""
        return Paso(self.m.ruta, ln, getattr(n, "col_offset", 0), cod, texto)

    def preparar_parametros(self, real: bool, entrada) -> None:
        f = self.f
        if real:
            self.entrada_tipo = entrada[0]
        omitir_self = bool(f.clase) and not f.estatico
        if omitir_self and f.params:
            self.tipos[f.params[0]] = f.clase
        for i, nombre in enumerate(f.params):
            if omitir_self and i == 0:
                continue
            if nombre in f.anotaciones:
                c = self.p.resolver_clase(self.m, f.anotaciones[nombre])
                if c:
                    self.tipos[nombre] = c.id
            if real:
                tipo, cuales = entrada
                if cuales == "todos" or i in cuales:
                    t = Taint(tipo, self.paso(f.nodo, f"{ETIQUETA_ORIGEN.get(tipo, tipo)}: parámetro "
                                                       f"'{nombre}' de {f.nombre}()"))
                    self.env[nombre] = Taints([t])
                    self.entrada_tipo = tipo
            else:
                t = Taint(f"param:{i}", self.paso(f.nodo, f"parámetro '{nombre}'"))
                self.env[nombre] = Taints([t])
        extra = []
        if f.vararg:
            extra.append((f.vararg, f.indice_vararg()))
        if f.kwarg:
            extra.append((f.kwarg, f.indice_kwarg()))
        for nombre, i in extra:
            if real:
                tipo, cuales = entrada
                if cuales == "todos":
                    self.env[nombre] = Taints([Taint(tipo, self.paso(f.nodo, f"{ETIQUETA_ORIGEN.get(tipo, tipo)}: "
                                                                             f"'{nombre}' de {f.nombre}()"))])
            else:
                self.env[nombre] = Taints([Taint(f"param:{i}", self.paso(f.nodo, f"parámetro '{nombre}'"))])

    # ------------------------------------------------------------------ nombres
    def qn(self, n, env=None) -> str | None:
        base, attrs, _ = descomponer(n)
        if base is None:
            return None
        env = self.env if env is None else env
        if base in self.imps:
            return ".".join([self.imps[base]] + attrs)
        if base in env or base in self.tipos or base in self.funcs_locales:
            return None
        if not attrs:
            return base
        return None

    def receptor(self, n) -> str:
        """Nombre del objeto sobre el que se llama (para decidir por el nombre de la variable)."""
        if isinstance(n, ast.Attribute):
            v = n.value
            if isinstance(v, ast.Attribute):
                return v.attr
            if isinstance(v, ast.Name):
                return v.id
            if isinstance(v, ast.Call):
                b, at, _ = descomponer(v.func)
                return (at[-1] if at else b) or ""
        return ""

    # ------------------------------------------------------------------ ejecución de sentencias
    def ejecutar(self, stmts, env) -> None:
        for s in stmts:
            self.sentencia(s, env)

    def sentencia(self, s, env) -> None:
        t = type(s)
        if t is ast.Assign:
            v = self.ev(s.value, env)
            for tg in s.targets:
                self.asignar(tg, v, env, s.value)
        elif t is ast.AnnAssign:
            if s.value is not None:
                self.asignar(s.target, self.ev(s.value, env), env, s.value)
        elif t is ast.AugAssign:
            v = self.ev(s.value, env)
            actual = self.ev(s.target, env) if isinstance(s.target, (ast.Name, ast.Attribute, ast.Subscript)) else VACIO
            self.asignar(s.target, actual.union(v), env, s.value)
        elif t is ast.Expr:
            self.ev(s.value, env)
        elif t is ast.Return:
            if s.value is not None:
                v = self.ev(s.value, env)
                if v:
                    v = v.con_paso(self.paso(s, "devuelto por la función"))
                    self.retorno = self.retorno.union(v)
                    self._retorno_web(s, v)
        elif t is ast.If:
            self.si(s, env)
        elif t in (ast.For, ast.AsyncFor):
            self.bucle_for(s, env)
        elif t is ast.While:
            self.ev(s.test, env)
            self.repetir(s.body, env)
            self.ejecutar(s.orelse, env)
        elif t in (ast.With, ast.AsyncWith):
            for it in s.items:
                v = self.ev(it.context_expr, env)
                if it.optional_vars is not None:
                    self.asignar(it.optional_vars, v, env, it.context_expr)
            self.ejecutar(s.body, env)
        elif t is ast.Try or t.__name__ == "TryStar":
            self.intentar(s, env)
        elif t in (ast.FunctionDef, ast.AsyncFunctionDef):
            if self.f is not None:
                self.funcs_locales[s.name] = f"{self.m.nombre}:{self.f.qual}.{s.name}"
                self.defs_locales[s.name] = s
        elif t is ast.ClassDef:
            pass
        elif t is ast.Raise:
            if s.exc is not None:
                self.ev(s.exc, env)
        elif t is ast.Assert:
            self.ev(s.test, env)
        elif t is ast.Delete:
            for tg in s.targets:
                if isinstance(tg, ast.Name):
                    env.pop(tg.id, None)
        elif t is ast.Global or t is ast.Nonlocal:
            self.globales_decl.update(s.names)
        elif t is ast.Match:
            sujeto = self.ev(s.subject, env)
            salidas = []
            for c in s.cases:
                e2 = dict(env)
                for nodo in ast.walk(c.pattern):
                    nombre = getattr(nodo, "name", None) or getattr(nodo, "rest", None)
                    if isinstance(nombre, str):
                        e2[nombre] = sujeto
                if c.guard is not None:
                    self.ev(c.guard, e2)
                self.ejecutar(c.body, e2)
                salidas.append(e2)
            for e2 in salidas:
                self.unir(env, e2)
        elif t in (ast.Import, ast.ImportFrom, ast.Pass, ast.Break, ast.Continue):
            pass

    # --- asignación -----------------------------------------------------
    def asignar(self, tg, v: Taints, env, valor_nodo=None) -> None:
        if isinstance(tg, ast.Name):
            nuevo = v.con_paso(self.paso(tg, f"se guarda en '{tg.id}'")) if v else VACIO
            for k in [k for k in env if k.startswith(tg.id + "[")]:
                del env[k]
            if isinstance(valor_nodo, ast.Lambda):
                self.lambdas[tg.id] = valor_nodo
            else:
                self.lambdas.pop(tg.id, None)
            if isinstance(valor_nodo, ast.Dict) and valor_nodo.keys and all(
                    isinstance(k, ast.Constant) and isinstance(k.value, str) for k in valor_nodo.keys):
                for k, vv in zip(valor_nodo.keys, valor_nodo.values):
                    env[f"{tg.id}[{k.value}]"] = self.ev(vv, env)
            env[tg.id] = nuevo
            self._tipo_asignado(tg.id, valor_nodo)
            if tg.id in self.globales_decl and not self.modo_modulo:
                g = self.mo.globales[self.m.nombre]
                g[tg.id] = g.get(tg.id, VACIO).union(self._solo_reales(nuevo))
        elif isinstance(tg, (ast.Tuple, ast.List)):
            if isinstance(valor_nodo, (ast.Tuple, ast.List)) and len(valor_nodo.elts) == len(tg.elts) \
                    and not any(isinstance(x, ast.Starred) for x in tg.elts + valor_nodo.elts):
                for a, b in zip(tg.elts, valor_nodo.elts):
                    self.asignar(a, self.ev(b, env), env, b)
            else:
                for e in tg.elts:
                    self.asignar(e.value if isinstance(e, ast.Starred) else e, v, env, None)
        elif isinstance(tg, ast.Attribute):
            base, attrs, _ = descomponer(tg)
            clave = f"{base}.{'.'.join(attrs)}" if base else None
            if clave:
                env[clave] = v.con_paso(self.paso(tg, f"se guarda en '{clave}'")) if v else VACIO
            cid = self.tipos.get(base) if base and len(attrs) == 1 else None
            if cid:
                self._escribir_campo(cid, tg.attr, v, tg)
                if valor_nodo is not None:
                    t = self._tipo_de(valor_nodo)
                    if t:
                        self.mo.campo_tipos[(cid, tg.attr)] = t
        elif isinstance(tg, ast.Subscript):
            base, attrs, _ = descomponer(tg.value)
            if base and not attrs and isinstance(tg.slice, ast.Constant) and isinstance(tg.slice.value, str):
                env[f"{base}[{tg.slice.value}]"] = v
            elif base and not attrs:
                for k in [k for k in env if k.startswith(base + "[")]:
                    del env[k]
            if base and not attrs:
                env[base] = env.get(base, VACIO).union(v)
            elif base:
                clave = f"{base}.{'.'.join(attrs)}"
                env[clave] = env.get(clave, VACIO).union(v)
        elif isinstance(tg, ast.Starred):
            self.asignar(tg.value, v, env, None)

    def _solo_reales(self, v: Taints) -> Taints:
        return Taints(t for t in v if not t.simbolico)

    def _escribir_campo(self, cid: str, attr: str, v: Taints, nodo) -> None:
        if not v:
            return
        for c in self.p.mro(cid):
            k = (c.id, attr)
            reales = Taints(t for t in v if not t.simbolico)
            if reales:
                self.mo.campos[k] = self.mo.campos.get(k, VACIO).union(reales)
        k = (cid, attr)
        simb = Taints(t for t in v if t.simbolico)
        if simb:
            self.campos_resumen[k] = self.campos_resumen.get(k, VACIO).union(simb)

    def _leer_campo(self, cid: str, attr: str) -> Taints:
        r = VACIO
        for c in self.p.mro(cid):
            r = r.union(self.mo.campos.get((c.id, attr), VACIO))
        return r

    # --- tipos ------------------------------------------------------------
    def _tipo_asignado(self, nombre: str, valor) -> None:
        t = self._tipo_de(valor) if valor is not None else None
        if t:
            self.tipos[nombre] = t
        elif valor is not None and nombre in self.tipos:
            es_self = bool(self.f and self.f.clase and self.f.params and nombre == self.f.params[0])
            if not es_self:
                del self.tipos[nombre]

    def _tipo_de(self, v) -> str | None:
        if isinstance(v, ast.Call):
            base, attrs, _ = descomponer(v.func)
            if base is None:
                return None
            nombre = ".".join([base] + attrs)
            c = self.p.resolver_clase(self.m, nombre)
            if c:
                return c.id
        elif isinstance(v, ast.Name):
            return self.tipos.get(v.id)
        elif isinstance(v, ast.Attribute):
            base, attrs, _ = descomponer(v)
            if base and len(attrs) == 1 and self.tipos.get(base):
                return self.mo.campo_tipos.get((self.tipos[base], attrs[0]))
        return None

    # --- control de flujo --------------------------------------------------
    def unir(self, destino: dict, otro: dict) -> None:
        for k, v in otro.items():
            actual = destino.get(k)
            destino[k] = v if actual is None else actual.union(v)

    def terminal(self, stmts) -> bool:
        if not stmts:
            return False
        u = stmts[-1]
        if isinstance(u, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
            return True
        if isinstance(u, ast.Expr) and isinstance(u.value, ast.Call):
            b, at, _ = descomponer(u.value.func)
            nombre = at[-1] if at else b
            return nombre in TERMINADORES
        if isinstance(u, ast.If) and u.orelse:
            return self.terminal(u.body) and self.terminal(u.orelse)
        return False

    def si(self, s: ast.If, env) -> None:
        self.ev(s.test, env)
        g_si, g_no = self.guardas(s.test)
        e_si = dict(env)
        self.aplicar_guardas(e_si, g_si)
        self.ejecutar(s.body, e_si)
        e_no = dict(env)
        self.aplicar_guardas(e_no, g_no)
        self.ejecutar(s.orelse, e_no)
        t_si, t_no = self.terminal(s.body), self.terminal(s.orelse)
        if t_si and not t_no:
            nuevo = e_no
        elif t_no and not t_si:
            nuevo = e_si
        elif t_si and t_no:
            nuevo = e_si
            self.unir(nuevo, e_no)
        else:
            nuevo = e_si
            self.unir(nuevo, e_no)
        env.clear()
        env.update(nuevo)

    def aplicar_guardas(self, env, guardas) -> None:
        for nombre, clases in guardas:
            if nombre in env:
                env[nombre] = env[nombre].limpiar(clases)

    def _nombre_guardado(self, n) -> str | None:
        """Variable que protege una comprobación (atraviesa conversiones simples)."""
        for _ in range(6):
            if isinstance(n, ast.Name):
                return n.id
            if isinstance(n, ast.Attribute):
                base, attrs, _ = descomponer(n)
                if base:
                    return f"{base}.{'.'.join(attrs)}"
                _b, _a, nodo = descomponer(n)
                if isinstance(nodo, (ast.Call, ast.Subscript)):
                    n = nodo
                    continue
                return None
            if isinstance(n, ast.Subscript):
                n = n.value
                continue
            if isinstance(n, ast.Call):
                if isinstance(n.func, ast.Attribute) and not n.args:
                    n = n.func.value
                elif n.args:
                    n = n.args[0]
                else:
                    return None
            else:
                return None
        return None

    def guardas(self, test):
        """(guardas si es verdadero, guardas si es falso); cada guarda es (variable, clases)."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            a, b = self.guardas(test.operand)
            return b, a
        if isinstance(test, ast.BoolOp):
            partes = [self.guardas(v) for v in test.values]
            if isinstance(test.op, ast.And):
                return [g for p in partes for g in p[0]], []
            return [], [g for p in partes for g in p[1]]
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            nombre = self._nombre_guardado(test.left)
            op, comp = test.ops[0], test.comparators[0]
            if nombre:
                if isinstance(op, (ast.In, ast.NotIn)) and self._es_coleccion_fija(comp):
                    g = [(nombre, TODO)]
                    return (g, []) if isinstance(op, ast.In) else ([], g)
                if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comp, ast.Constant):
                    g = [(nombre, TODO)]
                    return (g, []) if isinstance(op, ast.Eq) else ([], g)
            return [], []
        if isinstance(test, ast.Call):
            base, attrs, _ = descomponer(test.func)
            nombre_f = attrs[-1] if attrs else base
            if isinstance(test.func, ast.Attribute):
                n = self._nombre_guardado(test.func.value)
                if n and nombre_f in ("isdigit", "isalnum", "isalpha", "isnumeric", "isidentifier", "isdecimal"):
                    return [(n, TODO)], []
                if n and nombre_f in ("startswith",) and test.args:
                    a0 = test.args[0]
                    if isinstance(a0, ast.Constant) and isinstance(a0.value, str) and len(a0.value) >= 2 \
                            and a0.value != "//":
                        return [(n, frozenset({"path", "ssrf", "redirect"}))], []
                    if not isinstance(a0, ast.Constant):
                        return [(n, frozenset({"path"}))], []
                    return [], []
                if n and nombre_f in ("is_relative_to",):
                    return [(n, frozenset({"path"}))], []
            if isinstance(test.func, ast.Attribute) and nombre_f == "fullmatch" and len(test.args) == 1:
                n = self._nombre_guardado(test.args[0])
                if n:
                    return [(n, TODO)], []
            qn = self.qn(test.func)
            if qn in ("re.fullmatch",) and len(test.args) >= 2:
                n = self._nombre_guardado(test.args[1])
                if n:
                    return [(n, TODO)], []
            if qn in ("os.path.commonpath", "os.path.commonprefix") and test.args:
                return [], []
            if qn in ("isinstance",) and test.args:
                n = self._nombre_guardado(test.args[0])
                if n and len(test.args) > 1 and _es_tipo_numerico(test.args[1]):
                    return [(n, TODO)], []
        return [], []

    def _es_coleccion_fija(self, n) -> bool:
        if isinstance(n, (ast.Tuple, ast.List, ast.Set)):
            return all(isinstance(e, ast.Constant) for e in n.elts)
        if isinstance(n, ast.Name):
            return n.id.isupper()
        if isinstance(n, ast.Attribute):
            return n.attr.isupper()
        if isinstance(n, ast.Constant):
            return isinstance(n.value, str)
        return False

    def bucle_for(self, s, env) -> None:
        it = self.ev(s.iter, env)
        self.asignar(s.target, it, env, None)
        self.repetir(s.body, env)
        self.ejecutar(s.orelse, env)

    def repetir(self, cuerpo, env) -> None:
        antes = {k: v.claves() for k, v in env.items()}
        e1 = dict(env)
        self.ejecutar(cuerpo, e1)
        self.unir(env, e1)
        despues = {k: v.claves() for k, v in env.items()}
        if despues != antes:
            e2 = dict(env)
            self.ejecutar(cuerpo, e2)
            self.unir(env, e2)

    def intentar(self, s, env) -> None:
        e_cuerpo = dict(env)
        self.ejecutar(s.body, e_cuerpo)
        salidas = [e_cuerpo]
        for h in s.handlers:
            e2 = dict(env)
            self.unir(e2, e_cuerpo)
            if h.name:
                e2[h.name] = VACIO
            self.ejecutar(h.body, e2)
            if not self.terminal(h.body):
                salidas.append(e2)
        if s.orelse:
            e3 = dict(e_cuerpo)
            self.ejecutar(s.orelse, e3)
            salidas[0] = e3
        final = salidas[0]
        for e in salidas[1:]:
            self.unir(final, e)
        env.clear()
        env.update(final)
        self.ejecutar(s.finalbody, env)

    # ------------------------------------------------------------------ retorno de rutas web
    def _retorno_web(self, s: ast.Return, v: Taints) -> None:
        if self.entrada_tipo != "http" or not self.mo.es_flask(self.m.nombre) or not self.mo.reportar:
            return
        val = s.value
        if isinstance(val, ast.Tuple) and val.elts:
            val = val.elts[0]
        if isinstance(val, ast.Call):
            b, at, _ = descomponer(val.func)
            if (at[-1] if at else b) not in ("format", "format_map", "join"):
                if self.resolver_destino(val.func, self.qn(val.func), b, at, self.env) is None:
                    return
        elif not isinstance(val, (ast.JoinedStr, ast.BinOp, ast.Name, ast.Attribute, ast.Subscript)):
            return
        for t in v:
            if t.simbolico or t.tipo in ORIGENES_LOCALES:
                continue
            self.llegada(t, "xss", "respuesta HTML", "media" if isinstance(val, (ast.Name, ast.Attribute,
                                                                                  ast.Subscript)) else "alta", s)

    # ------------------------------------------------------------------ expresiones
    def ev(self, n, env) -> Taints:
        t = type(n)
        if t is ast.Constant:
            return VACIO
        if t is ast.Name:
            return self.ev_nombre(n, env)
        if t is ast.Attribute:
            return self.ev_atributo(n, env)
        if t is ast.Call:
            return self.ev_llamada(n, env)
        if t is ast.Subscript:
            if isinstance(n.value, ast.Name) and isinstance(n.slice, ast.Constant) \
                    and isinstance(n.slice.value, str):
                por_clave = env.get(f"{n.value.id}[{n.slice.value}]")
                if por_clave is not None:
                    return por_clave
            base = self.ev(n.value, env)
            self.ev(n.slice, env)
            return base
        if t is ast.BinOp:
            return self.ev(n.left, env).union(self.ev(n.right, env))
        if t is ast.BoolOp:
            r = VACIO
            for v in n.values:
                r = r.union(self.ev(v, env))
            return r
        if t is ast.Compare:
            self.ev(n.left, env)
            for c in n.comparators:
                self.ev(c, env)
            return VACIO
        if t is ast.UnaryOp:
            v = self.ev(n.operand, env)
            return VACIO if isinstance(n.op, ast.Not) else v
        if t is ast.IfExp:
            self.ev(n.test, env)
            g_si, g_no = self.guardas(n.test)
            e1, e2 = dict(env), dict(env)
            self.aplicar_guardas(e1, g_si)
            self.aplicar_guardas(e2, g_no)
            return self.ev(n.body, e1).union(self.ev(n.orelse, e2))
        if t is ast.JoinedStr:
            r = VACIO
            for v in n.values:
                if isinstance(v, ast.FormattedValue):
                    r = r.union(self.ev(v.value, env))
            return r
        if t is ast.FormattedValue:
            return self.ev(n.value, env)
        if t in (ast.List, ast.Tuple, ast.Set):
            r = VACIO
            for e in n.elts:
                r = r.union(self.ev(e.value if isinstance(e, ast.Starred) else e, env))
            return r
        if t is ast.Dict:
            r = VACIO
            for k, v in zip(n.keys, n.values):
                if k is not None:
                    r = r.union(self.ev(k, env))
                r = r.union(self.ev(v, env))
            return r
        if t is ast.Starred or t is ast.Await:
            return self.ev(n.value, env)
        if t is ast.NamedExpr:
            v = self.ev(n.value, env)
            self.asignar(n.target, v, env, n.value)
            return v
        if t in (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp):
            e2 = dict(env)
            for g in n.generators:
                self.asignar(g.target, self.ev(g.iter, e2), e2, None)
                for c in g.ifs:
                    self.ev(c, e2)
            if t is ast.DictComp:
                return self.ev(n.key, e2).union(self.ev(n.value, e2))
            return self.ev(n.elt, e2)
        if t in (ast.Yield, ast.YieldFrom):
            if n.value is not None:
                v = self.ev(n.value, env)
                self.retorno = self.retorno.union(v)
                return v
            return VACIO
        if t is ast.Lambda:
            return VACIO
        if t is ast.Slice:
            for x in (n.lower, n.upper, n.step):
                if x is not None:
                    self.ev(x, env)
            return VACIO
        return VACIO

    def ev_nombre(self, n: ast.Name, env) -> Taints:
        v = env.get(n.id)
        if v is not None:
            return v
        qn = self.imps.get(n.id)
        if qn:
            f = self.cat.fuente_objeto(qn)
            if f:
                return self.fuente(f.tipo, n, n.id)
            if "." in qn:
                mod, _, nombre = qn.rpartition(".")
                mm = self.p.buscar_modulo(mod)
                if mm:
                    g = self.mo.globales.get(mm.nombre, {}).get(nombre)
                    if g is not None:
                        return g
        if not self.modo_modulo:
            g = self.mo.globales[self.m.nombre].get(n.id)
            if g is not None:
                return g
        return VACIO

    def fuente(self, tipo: str, nodo, texto: str) -> Taints:
        return Taints([Taint(tipo, self.paso(nodo, f"{ETIQUETA_ORIGEN.get(tipo, tipo)}: {texto}"))])

    def ev_atributo(self, n: ast.Attribute, env) -> Taints:
        base, attrs, _ = descomponer(n)
        qn = self.qn(n, env)
        if qn:
            f = self.cat.fuente_objeto(qn)
            if f:
                return self.fuente(f.tipo, n, _src(n))
        if base:
            clave = f"{base}.{'.'.join(attrs)}"
            if clave in env:
                return env[clave]
            if len(attrs) == 1:
                cid = self.tipos.get(base)
                if cid:
                    campo = self._leer_campo(cid, attrs[0])
                    return campo if campo else VACIO
        v = self.ev(n.value, env)
        if v and n.attr in ("name", "stem", "suffix", "suffixes"):
            v = v.limpiar({"path"})
        return v

    # ------------------------------------------------------------------ llamadas
    def ev_llamada(self, n: ast.Call, env) -> Taints:
        func = n.func
        base, attrs, _ = descomponer(func)
        qn = self.qn(func, env)
        nombre = attrs[-1] if attrs else (base or "")
        recv = self.receptor(func)

        rec = VACIO
        if isinstance(func, ast.Attribute):
            rec = self.ev(func.value, env)
        elif not isinstance(func, ast.Name):
            rec = self.ev(func, env)

        pos: list[Taints] = []
        extra = VACIO
        parar = False
        for a in n.args:
            if isinstance(a, ast.Starred):
                extra = extra.union(self.ev(a.value, env))
                parar = True
            else:
                v = self.ev(a, env)
                if parar:
                    extra = extra.union(v)
                else:
                    pos.append(v)
        kw: dict = {}
        for k in n.keywords:
            v = self.ev(k.value, env)
            if k.arg is None:
                extra = extra.union(v)
            else:
                kw[k.arg] = v
        todos = rec.union(extra)
        for v in pos:
            todos = todos.union(v)
        for v in kw.values():
            todos = todos.union(v)

        # --- fuentes
        resultado = VACIO
        fuentes = self.cat.fuentes_de_llamada(qn, attrs, recv)
        for f in fuentes:
            resultado = resultado.union(self.fuente(f.tipo, n, _src(func)))

        # --- lambdas y funciones anidadas: se ejecutan en línea (ven las variables capturadas)
        if isinstance(func, ast.Name) and not attrs:
            if func.id in self.lambdas:
                lam = self.lambdas[func.id]
                return resultado.union(self._en_linea(lam.args, lam.body, True, pos, kw, extra, env))
            if func.id in self.defs_locales:
                d = self.defs_locales[func.id]
                return resultado.union(self._en_linea(d.args, d.body, False, pos, kw, extra, env))

        # --- llamadas indirectas: Thread(target=f, args=(x,)), pool.submit(f, x), ...
        self._llamada_indirecta(n, qn, nombre, pos, kw, env)

        # --- resolución de funciones del proyecto
        destino = self.resolver_destino(func, qn, base, attrs, env)

        # --- sumideros
        ss = self.cat.sumideros_de(qn, attrs, recv, usar_colas=destino is None)
        if ss:
            self.revisar_sumideros(n, ss, pos, kw, extra, rec, func)

        # --- mutadores (lista.append(x), buffer.write(x), ...)
        if isinstance(func, ast.Attribute) and nombre in METODOS_MUTADORES and destino is None:
            clave = self._clave_receptor(func.value)
            if clave:
                for k in [k for k in env if k.startswith(clave + "[")]:
                    del env[k]
                add = extra
                for v in pos:
                    add = add.union(v)
                for v in kw.values():
                    add = add.union(v)
                if add:
                    env[clave] = env.get(clave, VACIO).union(add)

        # --- saneadores
        san = self.cat.saneador(qn)
        if san is not None:
            return resultado.union(todos.limpiar(san).con_paso(self.paso(n, f"saneado con {_src(func, 40)}")))
        if qn in ("re.sub", "regex.sub") and len(n.args) >= 3 and _lista_blanca(n.args[0], n.args[1]):
            return resultado.union(self.ev(n.args[2], env).limpiar(TODO))
        if nombre == "replace" and isinstance(func, ast.Attribute) and n.args \
                and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str) \
                and ("\n" in n.args[0].value or "\r" in n.args[0].value):
            return resultado.union(rec.limpiar({"log"}).union(extra))
        if (qn in LIMPIAN_TODO) or (qn is None and not attrs and base in LIMPIAN_TODO):
            return resultado
        if isinstance(func, ast.Attribute) and nombre in METODOS_LIMPIOS and destino is None:
            return resultado

        # --- funciones del proyecto
        if destino is not None:
            f, salta_self, es_clase = destino
            return resultado.union(self.aplicar_resumen(n, f, pos, kw, extra, rec, salta_self))
        if self._es_constructor_proyecto(func):
            return resultado.union(self._construir_sin_init(n, func, pos, kw, extra))

        # --- bibliotecas desconocidas o conocidas
        if fuentes and not todos:
            return resultado
        conocido = nombre in PROPAGA_CONOCIDOS or (qn is not None and qn.rsplit(".", 1)[-1] in PROPAGA_CONOCIDOS)
        if not todos:
            return resultado
        out = todos.con_paso(self.paso(n, f"pasa por {_src(func, 40)}()"))
        if not conocido:
            out = out.marcar_incierto()
        return resultado.union(out)

    def _en_linea(self, args: ast.arguments, cuerpo, es_lambda: bool, pos, kw, extra, env) -> Taints:
        clave = id(args)
        if clave in self._inline or len(self._inline) >= 4:
            return VACIO
        self._inline.add(clave)
        try:
            e2 = dict(env)
            params = [a.arg for a in args.posonlyargs + args.args + args.kwonlyargs]
            for i, nombre in enumerate(params):
                v = pos[i] if i < len(pos) else kw.get(nombre, VACIO)
                e2[nombre] = v.union(extra) if extra else v
            if args.vararg:
                resto = VACIO
                for v in pos[len(params):]:
                    resto = resto.union(v)
                e2[args.vararg.arg] = resto.union(extra)
            if args.kwarg:
                resto = extra
                for nombre, v in kw.items():
                    if nombre not in params:
                        resto = resto.union(v)
                e2[args.kwarg.arg] = resto
            if es_lambda:
                return self.ev(cuerpo, e2)
            antes, self.retorno = self.retorno, VACIO
            self.ejecutar(cuerpo, e2)
            r, self.retorno = self.retorno, antes
            return r
        finally:
            self._inline.discard(clave)

    def _llamada_indirecta(self, n, qn, nombre, pos, kw, env) -> None:
        """Hilos y ejecutores: el objetivo se llama con los argumentos indicados."""
        objetivo = None
        argumentos: list = []
        kwargs: dict = {}
        if nombre in ("Thread", "Process", "Timer"):
            for k in n.keywords:
                if k.arg == "target":
                    objetivo = k.value
                elif k.arg == "args":
                    if isinstance(k.value, (ast.Tuple, ast.List)):
                        argumentos = [self.ev(e, env) for e in k.value.elts]
                    else:
                        argumentos = [self.ev(k.value, env)]
                elif k.arg == "kwargs" and isinstance(k.value, ast.Dict):
                    for kk, vv in zip(k.value.keys, k.value.values):
                        if isinstance(kk, ast.Constant) and isinstance(kk.value, str):
                            kwargs[kk.value] = self.ev(vv, env)
        elif nombre in ("submit", "apply_async", "run_in_executor", "start_new_thread", "call_soon",
                        "call_later", "to_thread", "run_in_threadpool") and n.args:
            idx = 1 if nombre == "run_in_executor" else 0
            if nombre == "call_later":
                idx = 1
            if idx < len(n.args):
                objetivo = n.args[idx]
                argumentos = list(pos[idx + 1:])
                for a in ((n.args[idx + 1],) if nombre == "apply_async" and len(n.args) > idx + 1 else ()):
                    if isinstance(a, (ast.Tuple, ast.List)):
                        argumentos = [self.ev(e, env) for e in a.elts]
                kwargs = dict(kw)
        if objetivo is None:
            return
        if isinstance(objetivo, ast.Name):
            if objetivo.id in self.lambdas:
                lam = self.lambdas[objetivo.id]
                self._en_linea(lam.args, lam.body, True, argumentos, kwargs, VACIO, env)
                return
            if objetivo.id in self.defs_locales:
                d = self.defs_locales[objetivo.id]
                self._en_linea(d.args, d.body, False, argumentos, kwargs, VACIO, env)
                return
        elif isinstance(objetivo, ast.Lambda):
            self._en_linea(objetivo.args, objetivo.body, True, argumentos, kwargs, VACIO, env)
            return
        base, attrs, _ = descomponer(objetivo)
        destino = self.resolver_destino(objetivo, self.qn(objetivo, env), base, attrs, env)
        if destino is not None:
            f, salta_self, _es = destino
            self.aplicar_resumen(n, f, argumentos, kwargs, VACIO, VACIO, salta_self)

    def _clave_receptor(self, v) -> str | None:
        base, attrs, _ = descomponer(v)
        if base is None:
            return None
        return base if not attrs else f"{base}.{'.'.join(attrs)}"

    # --- resolución -----------------------------------------------------------
    def resolver_destino(self, func, qn, base, attrs, env):
        """(FuncInfo, saltar_self, es_clase) o None."""
        p = self.p
        # super().metodo()
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Call) \
                and isinstance(func.value.func, ast.Name) and func.value.func.id == "super" and self.clase_id:
            for c in p.mro(self.clase_id)[1:]:
                if func.attr in c.metodos:
                    return c.metodos[func.attr], True, False
            return None
        if isinstance(func, ast.Name):
            nm = func.id
            fid = self.funcs_locales.get(nm)
            if fid and fid in p.funcs:
                return p.funcs[fid], False, False
            if self.f is not None:
                fid = f"{self.m.nombre}:{self.f.qual}.{nm}"
                if fid in p.funcs:
                    return p.funcs[fid], False, False
            if nm not in self.imps and nm not in env:
                fid = f"{self.m.nombre}:{nm}"
                if fid in p.funcs:
                    return p.funcs[fid], False, False
                c = p.buscar_clase(self.m.nombre, nm)
                if c:
                    return self._init_de(c)
        if qn and (base in self.imps or isinstance(func, ast.Name)):
            r = self._resolver_qn(qn)
            if r:
                return r
        if isinstance(func, ast.Attribute):
            # Clase(...).metodo(...)
            if isinstance(func.value, ast.Call) and not (
                    isinstance(func.value.func, ast.Name) and func.value.func.id == "super"):
                cid = self._tipo_de(func.value)
                if cid:
                    f = p.metodo(cid, func.attr)
                    if f:
                        return f, not f.estatico, False
            # método sobre variable con tipo conocido
            if base and base not in self.imps:
                cid = None
                if len(attrs) == 1:
                    cid = self.tipos.get(base)
                elif len(attrs) == 2:
                    t0 = self.tipos.get(base)
                    cid = self.mo.campo_tipos.get((t0, attrs[0])) if t0 else None
                if cid:
                    f = p.metodo(cid, attrs[-1])
                    if f:
                        return f, not f.estatico, False
                # ClaseLocal.metodo(...)
                if len(attrs) == 1 and base not in env:
                    c = p.buscar_clase(self.m.nombre, base)
                    if c:
                        f = p.metodo(c.id, attrs[0])
                        if f:
                            return f, False, False
            # método de nombre único en el proyecto
            if attrs and attrs[-1] not in METODOS_COMUNES and not (qn and self.cat.sumideros_de(qn, attrs, "", False)):
                alcance = self.mo.alcance(self.m)
                cands = [c for c in p.por_metodo.get(attrs[-1], []) if c.modulo in alcance]
                if len(cands) == 1 and not attrs[-1].startswith("__"):
                    return cands[0], not cands[0].estatico, False
        return None

    def _resolver_qn(self, qn: str):
        p = self.p
        partes = qn.split(".")
        for k in range(len(partes) - 1, 0, -1):
            mod = p.buscar_modulo(".".join(partes[:k]))
            if not mod:
                continue
            resto = ".".join(partes[k:])
            fid = f"{mod.nombre}:{resto}"
            if fid in p.funcs:
                return p.funcs[fid], False, False
            c = p.clases.get(f"{mod.nombre}:{resto}")
            if c:
                return self._init_de(c)
            if "." in resto:
                cn, _, mn = resto.rpartition(".")
                c = p.clases.get(f"{mod.nombre}:{cn}")
                if c:
                    f = p.metodo(c.id, mn)
                    if f:
                        return f, False, False
        return None

    def _init_de(self, c):
        f = self.p.metodo(c.id, "__init__")
        if f:
            return f, True, True
        return None

    def _es_constructor_proyecto(self, func) -> bool:
        base, attrs, _ = descomponer(func)
        if base is None:
            return False
        nombre = ".".join([base] + attrs)
        c = self.p.resolver_clase(self.m, nombre)
        return c is not None and (c.es_dataclass or bool(c.campos_anotados))

    def _construir_sin_init(self, n, func, pos, kw, extra) -> Taints:
        base, attrs, _ = descomponer(func)
        c = self.p.resolver_clase(self.m, ".".join([base] + attrs))
        if not c:
            return VACIO
        campos = list(c.campos_anotados)
        for i, v in enumerate(pos):
            if i < len(campos):
                self._escribir_campo(c.id, campos[i], v, n)
        for k, v in kw.items():
            self._escribir_campo(c.id, k, v, n)
        for campo in campos:
            self._escribir_campo(c.id, campo, extra, n)
        return VACIO

    # --- sumideros --------------------------------------------------------------
    def revisar_sumideros(self, n, ss, pos, kw, extra, rec, func) -> None:
        for s in ss:
            if s.cond and not self._cumple(s.cond, n, kw):
                continue
            if s.clase in ("ssrf", "redirect") and self._destino_fijo(s.clase, n):
                continue
            if s.cond == "subprocess":
                self._subprocess(n, s, pos, kw, extra)
                continue
            vistos = []
            for i in s.args:
                if i == "*":
                    for v in pos:
                        vistos.append(v)
                    vistos.extend(kw.values())
                elif i < len(pos):
                    vistos.append(pos[i])
            for k in s.kws:
                if k in kw:
                    vistos.append(kw[k])
            if s.receptor:
                vistos.append(rec)
            vistos.append(extra)
            self._llegadas(vistos, s.clase, s.etiqueta, s.confianza, n, func)

    def _prefijo_fijo(self, n) -> str:
        """Texto constante con el que empieza una expresión de texto (concatenación, f-string, %, format)."""
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            return n.value
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
            return self._prefijo_fijo(n.left)
        if isinstance(n, ast.JoinedStr) and n.values and isinstance(n.values[0], ast.Constant):
            return str(n.values[0].value)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format":
            return self._prefijo_fijo(n.func.value)
        return ""

    def _destino_fijo(self, clase: str, n: ast.Call) -> bool:
        """True si el dato solo puede cambiar la ruta, no el servidor (https://host/ + dato)."""
        a0 = n.args[0] if n.args else next((k.value for k in n.keywords if k.arg in ("url", "location")), None)
        if a0 is None:
            return False
        pre = self._prefijo_fijo(a0)
        if clase == "ssrf":
            return bool(re.match(r"^(https?://)[^/\\@?#]+/", pre))
        if clase == "redirect":
            return bool(re.match(r"^(https?://[^/\\@?#]+/|/[^/\\])", pre))
        return False

    def _llegadas(self, lista, clase, etiqueta, confianza, n, func) -> None:
        for v in lista:
            for t in v:
                self.llegada(t, clase, etiqueta, confianza, n, func)

    def _subprocess(self, n, s, pos, kw, extra) -> None:
        arg0 = n.args[0] if n.args else None
        if arg0 is None:
            for k in ("args",):
                for kk in n.keywords:
                    if kk.arg == k:
                        arg0 = kk.value
        shell = False
        for kk in n.keywords:
            if kk.arg == "shell":
                shell = not (isinstance(kk.value, ast.Constant) and not kk.value.value)
        v0 = pos[0] if pos else kw.get("args", VACIO)
        if shell:
            self._llegadas([v0, extra], "cmd", "comando con shell=True", "alta", n, n.func)
            return
        if isinstance(arg0, (ast.List, ast.Tuple)) and len(arg0.elts) >= 3 \
                and isinstance(arg0.elts[0], ast.Constant) and isinstance(arg0.elts[0].value, str) \
                and arg0.elts[0].value.rsplit("/", 1)[-1].lower() in ("sh", "bash", "zsh", "dash", "cmd", "cmd.exe",
                                                                       "powershell", "pwsh") \
                and isinstance(arg0.elts[1], ast.Constant) and str(arg0.elts[1].value).lower() in ("-c", "/c", "-command"):
            for e in arg0.elts[2:]:
                self._llegadas([self.ev(e.value if isinstance(e, ast.Starred) else e, self.env)], "cmd",
                               "comando pasado a un intérprete (sh -c)", "alta", n, n.func)
            self._llegadas([extra], "cmd", "comando pasado a un intérprete (sh -c)", "alta", n, n.func)
            return
        if isinstance(arg0, (ast.List, ast.Tuple)) and arg0.elts:
            primero = arg0.elts[0]
            if isinstance(primero, ast.Starred):
                self._llegadas([self.ev(primero.value, self.env)], "cmd_arg", "argumentos de subprocess", "media",
                               n, n.func)
            else:
                self._llegadas([self.ev(primero, self.env)], "cmd", "programa ejecutado por subprocess", "alta",
                               n, n.func)
            for e in arg0.elts[1:]:
                if isinstance(e, ast.Constant) and e.value == "--":
                    break  # tras «--» ya no se interpretan opciones
                self._llegadas([self.ev(e.value if isinstance(e, ast.Starred) else e, self.env)], "cmd_arg",
                               "argumentos de subprocess", "media", n, n.func)
        elif isinstance(arg0, (ast.Constant, type(None))):
            pass
        else:
            self._llegadas([v0], "cmd_arg", "argumentos de subprocess", "media", n, n.func)
        self._llegadas([extra], "cmd_arg", "argumentos de subprocess", "media", n, n.func)

    def _cumple(self, cond: str, n, kw) -> bool:
        def kwv(nombre):
            for k in n.keywords:
                if k.arg == nombre:
                    return k.value
            return None
        if cond == "sin_cargador_seguro":
            v = kwv("Loader") or (n.args[1] if len(n.args) > 1 else None)
            if v is None:
                return True
            nombre = _src(v)
            return nombre.split(".")[-1] not in SEGURAS_YAML
        if cond == "sin_weights_only":
            v = kwv("weights_only")
            return not (isinstance(v, ast.Constant) and v.value is True)
        if cond == "allow_pickle":
            v = kwv("allow_pickle")
            return isinstance(v, ast.Constant) and v.value is True
        if cond == "trust_remote_code":
            v = kwv("trust_remote_code")
            return isinstance(v, ast.Constant) and v.value is True
        return True

    # --- llegada de un dato a un sumidero ---------------------------------------
    def llegada(self, t: Taint, clase: str, etiqueta: str, confianza: str, n, func=None) -> None:
        if clase in t.limpio:
            return
        sink = self.paso(n, f"sumidero ({etiqueta}): {_src(func if func is not None else n, 60)}")
        if t.simbolico:
            k = int(t.tipo[6:])
            clave = (k, clase, sink.linea, sink.col, etiqueta)
            sp = SumParam(k, clase, etiqueta, confianza, t.pasos + (sink,))
            previo = self.sumideros.get(clave)
            if previo is None or len(sp.pasos) < len(previo.pasos):
                self.sumideros[clave] = sp
            return
        self._reportar(t, clase, etiqueta, confianza, sink, ())

    def _reportar(self, t: Taint, clase: str, etiqueta: str, confianza: str, sink: Paso, intermedios) -> None:
        if not self.mo.reportar:
            return
        if t.tipo in ORIGENES_LOCALES and clase not in CLASES_LOCALES:
            return
        if t.tipo == "red" and clase not in CLASES_RED:
            return
        if self.mo.estricto and t.incierto:
            return
        regla = REGLAS[clase]
        sev = regla.severidad
        if t.tipo in ORIGENES_LOCALES:
            sev = bajar(sev, 2)
        if t.tipo == "llm" and clase in ("log", "regex"):
            return
        conf = "media" if (t.tipo in ORIGENES_LOCALES and confianza == "alta") else confianza
        if t.incierto:
            conf = "baja" if conf != "alta" else "media"
        traza = [t.origen] + list(t.pasos) + list(intermedios) + [sink]
        origen = ETIQUETA_ORIGEN.get(t.tipo, t.tipo)
        msg = (f"{origen[0].upper() + origen[1:]} (línea {t.origen.linea}) llega sin sanear a "
               f"{sink.texto.split(':')[0].replace('sumidero (', '').rstrip(')')}"
               f" en {sink.ruta.rsplit('/', 1)[-1]}:{sink.linea}.")
        if t.incierto:
            msg += " El dato pasó por una función externa desconocida, así que la confianza es menor."
        h = Hallazgo(regla.id, clase, regla.titulo, regla.cwe, sev, conf, sink.ruta, sink.linea, sink.col,
                     sink.codigo, msg, regla.remedio, t.tipo, traza, owasp=regla.owasp)
        h.huella = huella(h)
        self.mo.registrar(h)

    # --- aplicación de resúmenes -------------------------------------------------
    def aplicar_resumen(self, n, f: FuncInfo, pos, kw, extra, rec, salta_self: bool) -> Taints:
        res = self.mo.resumenes.get(f.id)
        paso = self.paso(n, f"llamada a {f.nombre}()")
        amap: dict[int, Taints] = {}
        desp = 1 if (salta_self and f.params and not f.estatico) else 0
        for i, v in enumerate(pos):
            idx = i + desp
            if idx < len(f.params):
                amap[idx] = amap.get(idx, VACIO).union(v)
            elif f.vararg:
                amap[f.indice_vararg()] = amap.get(f.indice_vararg(), VACIO).union(v)
        for k, v in kw.items():
            if k in f.params:
                idx = f.params.index(k)
                amap[idx] = amap.get(idx, VACIO).union(v)
            elif f.kwarg:
                amap[f.indice_kwarg()] = amap.get(f.indice_kwarg(), VACIO).union(v)
        if extra:
            for idx in range(len(f.params)):
                if not (desp and idx == 0):
                    amap[idx] = amap.get(idx, VACIO).union(extra)
            if f.vararg:
                amap[f.indice_vararg()] = amap.get(f.indice_vararg(), VACIO).union(extra)
            if f.kwarg:
                amap[f.indice_kwarg()] = amap.get(f.indice_kwarg(), VACIO).union(extra)
        if res is None:
            return VACIO

        salida = VACIO
        for t in res.retorno:
            if t.simbolico:
                k = int(t.tipo[6:])
                for a in amap.get(k, ()):
                    salida = salida.union(Taints([self._sustituir(a, t, paso)]))
            else:
                salida = salida.union(Taints([t.con_paso(paso)]))

        for sp in res.sumideros.values():
            for a in amap.get(sp.param, ()):
                if sp.clase in a.limpio:
                    continue
                if a.simbolico:
                    k = int(a.tipo[6:])
                    clave = (k, sp.clase, sp.pasos[-1].linea, sp.pasos[-1].col, sp.etiqueta, f.id)
                    nuevo = SumParam(k, sp.clase, sp.etiqueta, sp.confianza,
                                     a.pasos + (paso,) + sp.pasos)
                    previo = self.sumideros.get(clave)
                    if previo is None or len(nuevo.pasos) < len(previo.pasos):
                        self.sumideros[clave] = nuevo
                else:
                    self._reportar(a, sp.clase, sp.etiqueta, sp.confianza, sp.pasos[-1],
                                   (paso,) + sp.pasos[:-1])

        for (cid, attr), ts in res.campos.items():
            for t in ts:
                if t.simbolico:
                    for a in amap.get(int(t.tipo[6:]), ()):
                        nuevo = self._sustituir(a, t, paso)
                        self._escribir_campo(cid, attr, Taints([nuevo]), n)
        return salida

    def _sustituir(self, arg: Taint, simbolo: Taint, paso: Paso) -> Taint:
        pasos = arg.pasos + (paso,) + simbolo.pasos
        if len(pasos) > 16:
            pasos = pasos[:5] + pasos[-11:]
        return replace(arg, pasos=pasos, limpio=arg.limpio | simbolo.limpio,
                       incierto=arg.incierto or simbolo.incierto)


def _lista_blanca(patron, reemplazo) -> bool:
    """re.sub(r"[^a-z0-9_]", "", x): borra todo lo que no esté en una lista corta de caracteres inocuos."""
    if not (isinstance(patron, ast.Constant) and isinstance(patron.value, str)):
        return False
    if not (isinstance(reemplazo, ast.Constant) and isinstance(reemplazo.value, str)
            and re.fullmatch(r"[A-Za-z0-9_\-]*", reemplazo.value)):
        return False
    mt = re.fullmatch(r"\[\^([^\]]+)\]\+?", patron.value)
    if not mt:
        return False
    permitidos = mt.group(1)
    for rango in ("a-z", "A-Z", "0-9", "\\w", "\\d"):
        permitidos = permitidos.replace(rango, "")
    return all(c in "_-." for c in permitidos) and "." not in permitidos or all(c in "_-" for c in permitidos)


def _es_tipo_numerico(n) -> bool:
    nombres = []
    if isinstance(n, ast.Tuple):
        nombres = [_src(e) for e in n.elts]
    else:
        nombres = [_src(n)]
    return all(x in ("int", "float", "bool", "complex") for x in nombres)


def huella(h: Hallazgo) -> str:
    """Identificador estable: no cambia si se mueve el código de línea."""
    o = h.traza[0]
    base = "|".join([h.regla, h.ruta, " ".join(h.codigo.split()), " ".join(o.codigo.split())])
    return hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]
