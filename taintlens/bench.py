"""Banco de pruebas: TaintLens frente a un escáner de patrones sin flujo y, si está instalado, Bandit."""
from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections import defaultdict

from . import __version__
from .catalogo import Catalogo
from .generador import CLASES_BENCH, Caso, generar_corpus
from .motor import Motor, descomponer
from .proyecto import Proyecto

# Bandit no es un analizador de flujo, solo tiene reglas para algunas clases.
BANDIT_REGLAS = {
    "cmd": {"B602", "B604", "B605", "B606"}, "sql": {"B608"}, "code": {"B307", "B102"},
    "deser": {"B301", "B302", "B506"}, "ssrf": {"B310"},
}
CLASES_FLUJO = {"cmd": {"cmd", "cmd_arg"}, "sql": {"sql"}, "path": {"path"}, "code": {"code"}, "deser": {"deser"},
                "ssrf": {"ssrf"}, "xss": {"xss"}, "ssti": {"ssti"}, "redirect": {"redirect"}}


# --------------------------------------------------------------------------- herramientas
def predecir_taintlens(caso: Caso, catalogo: Catalogo) -> bool:
    p = Proyecto.desde_fuentes({"app.py": caso.codigo})
    m = Motor(p, catalogo)
    hs = m.analizar()
    return any(h.clase in CLASES_FLUJO[caso.clase] for h in hs)


def predecir_patrones(caso: Caso, catalogo: Catalogo) -> bool:
    """Escáner sin flujo: marca cualquier punto sensible cuyo argumento no sea un literal."""
    p = Proyecto.desde_fuentes({"app.py": caso.codigo})
    clases = CLASES_FLUJO[caso.clase]
    for m in p.modulos.values():
        for n in ast.walk(m.arbol):
            if isinstance(n, ast.Call):
                base, attrs, _ = descomponer(n.func)
                if base is None:
                    continue
                qn = ".".join([m.imports[base]] + attrs) if base in m.imports else (base if not attrs else None)
                recv = attrs[-2] if len(attrs) > 1 else (base if attrs else "")
                for s in catalogo.sumideros_de(qn, attrs, recv):
                    if s.clase not in clases:
                        continue
                    args = [n.args[i] for i in s.args if isinstance(i, int) and i < len(n.args)]
                    args += [k.value for k in n.keywords if k.arg in s.kws]
                    if any(not isinstance(a, ast.Constant) for a in args):
                        return True
            elif isinstance(n, ast.Return) and caso.clase == "xss" and n.value is not None:
                if isinstance(n.value, (ast.JoinedStr, ast.BinOp)) or (
                        isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute)
                        and n.value.func.attr == "format"):
                    if not isinstance(n.value, ast.Constant):
                        return True
    return False


def _bandit_comando():
    exe = shutil.which("bandit")
    if exe:
        return [exe]
    try:
        import bandit  # noqa: F401
        return [sys.executable, "-m", "bandit"]
    except ImportError:
        return None


def correr_bandit(casos: list[Caso]):
    cmd = _bandit_comando()
    if cmd is None:
        return None, None
    with tempfile.TemporaryDirectory() as d:
        for c in casos:
            with open(os.path.join(d, c.id + ".py"), "w", encoding="utf-8") as f:
                f.write(c.codigo)
        try:
            r = subprocess.run(cmd + ["-r", d, "-f", "json", "-q"], capture_output=True, text=True, timeout=900)
            datos = json.loads(r.stdout or "{}")
        except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
            return None, None
    por_caso: dict = defaultdict(set)
    for res in datos.get("results", []):
        por_caso[os.path.basename(res["filename"])[:-3]].add(res["test_id"])
    version = ""
    try:
        import bandit
        version = getattr(bandit, "__version__", "")
    except ImportError:
        pass
    return por_caso, version


# --------------------------------------------------------------------------- métricas
class Cuenta:
    def __init__(self):
        self.tp = self.fp = self.fn = self.tn = 0

    def anadir(self, real: bool, pred: bool) -> None:
        if real and pred:
            self.tp += 1
        elif real:
            self.fn += 1
        elif pred:
            self.fp += 1
        else:
            self.tn += 1

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else 1.0

    @property
    def cobertura(self) -> float:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.cobertura
        return 2 * p * r / (p + r) if p + r else 0.0

    def a_dict(self) -> dict:
        return {"tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn, "precision": round(self.precision, 4),
                "cobertura": round(self.cobertura, 4), "f1": round(self.f1, 4)}


def medir(n_por_clase: int = 600, semilla: int = 1, con_bandit: bool = True) -> dict:
    casos = generar_corpus(n_por_clase, semilla)
    cat = Catalogo()
    herramientas = ["TaintLens", "Patrones (sin flujo)"]
    cuentas = {h: defaultdict(Cuenta) for h in herramientas}
    fallos: dict = defaultdict(list)
    t0 = time.perf_counter()
    lineas = 0
    tiempo_tl = 0.0
    for c in casos:
        lineas += c.codigo.count("\n")
        t1 = time.perf_counter()
        try:
            pt = predecir_taintlens(c, cat)
        except Exception as e:                       # un fallo del motor cuenta como no detectar
            pt = False
            fallos["__errores__"].append((c.id, repr(e)))
        tiempo_tl += time.perf_counter() - t1
        pp = predecir_patrones(c, cat)
        for h, pred in (("TaintLens", pt), ("Patrones (sin flujo)", pp)):
            cuentas[h][c.clase].anadir(c.vulnerable, pred)
            cuentas[h]["__total__"].anadir(c.vulnerable, pred)
            cuentas[h]["v:" + c.categoria.split("|")[-1] if c.vulnerable else "s:" + c.variante].anadir(c.vulnerable, pred)
        if pt != c.vulnerable:
            fallos[c.variante].append((c.id, "no detectado" if c.vulnerable else "falsa alarma"))
    # Bandit
    bandit_res = None
    if con_bandit:
        por_caso, version = correr_bandit(casos)
        if por_caso is not None:
            herramientas.append(f"Bandit {version}".strip())
            nombre = herramientas[-1]
            cuentas[nombre] = defaultdict(Cuenta)
            for c in casos:
                reglas = BANDIT_REGLAS.get(c.clase)
                if reglas is None:
                    continue
                pred = bool(por_caso.get(c.id, set()) & reglas)
                cuentas[nombre][c.clase].anadir(c.vulnerable, pred)
                cuentas[nombre]["__total__"].anadir(c.vulnerable, pred)
            bandit_res = nombre
    # los totales de Patrones y TaintLens sobre las clases que Bandit cubre (comparación justa)
    comun = {}
    if bandit_res:
        for h in ("TaintLens", "Patrones (sin flujo)"):
            tot = Cuenta()
            for cl in BANDIT_REGLAS:
                x = cuentas[h][cl]
                tot.tp += x.tp
                tot.fp += x.fp
                tot.fn += x.fn
                tot.tn += x.tn
            comun[h] = tot
        comun[bandit_res] = cuentas[bandit_res]["__total__"]
    return {"casos": len(casos), "vulnerables": sum(c.vulnerable for c in casos), "semilla": semilla,
            "n_por_clase": n_por_clase, "lineas": lineas, "segundos_taintlens": round(tiempo_tl, 2),
            "segundos_total": round(time.perf_counter() - t0, 2), "herramientas": herramientas,
            "cuentas": cuentas, "fallos": fallos, "comun": comun, "bandit": bandit_res}


# --------------------------------------------------------------------------- informe
def _fila(nombre: str, c: Cuenta) -> str:
    return (f"| {nombre} | {c.precision * 100:5.1f} % | {c.cobertura * 100:5.1f} % | {c.f1 * 100:5.1f} % "
            f"| {c.tp} | {c.fp} | {c.fn} | {c.tn} |")


def informe_md(r: dict) -> str:
    cu = r["cuentas"]
    L = ["# Banco de pruebas de TaintLens", "",
         f"- Programas generados: **{r['casos']}** ({r['vulnerables']} vulnerables y {r['casos'] - r['vulnerables']} seguros), "
         f"{r['n_por_clase']} por clase, semilla {r['semilla']}",
         f"- TaintLens {__version__}: {r['lineas'] / max(r['segundos_taintlens'], 0.001):,.0f} líneas por segundo "
         f"({r['segundos_taintlens']} s en total)".replace(",", "."), "",
         "> **Lee esto antes de fiarte de las cifras.** El corpus lo he generado yo con las mismas ideas con las que "
         "diseñé el motor. Mide que el motor es coherente y robusto con muchas formas de escribir lo mismo, "
         "no que encuentre el 99 % de las vulnerabilidades de cualquier proyecto real. Bandit no sigue datos y "
         "solo tiene reglas para algunas clases; la comparación está para ver la diferencia entre mirar patrones "
         "y seguir el dato.", "",
         "## Resultado global (todas las clases)", "",
         "| Herramienta | Precisión | Cobertura | F1 | VP | FP | FN | VN |", "|---|---|---|---|---|---|---|---|"]
    for h in ("TaintLens", "Patrones (sin flujo)"):
        L.append(_fila(h, cu[h]["__total__"]))
    if r["bandit"]:
        L += ["", f"## Solo las clases donde Bandit tiene reglas ({', '.join(sorted(BANDIT_REGLAS))})", "",
              "| Herramienta | Precisión | Cobertura | F1 | VP | FP | FN | VN |", "|---|---|---|---|---|---|---|---|"]
        for h in ("TaintLens", "Patrones (sin flujo)", r["bandit"]):
            L.append(_fila(h, r["comun"][h]))
    L += ["", "## Por clase de vulnerabilidad", "",
          "| Clase | TaintLens (F1) | Precisión | Cobertura | Patrones sin flujo (F1) |" +
          (f" {r['bandit']} (F1) |" if r["bandit"] else ""),
          "|---|---|---|---|---|" + ("---|" if r["bandit"] else "")]
    for cl in CLASES_BENCH:
        t, p = cu["TaintLens"][cl], cu["Patrones (sin flujo)"][cl]
        fila = f"| {cl} | {t.f1 * 100:.1f} % | {t.precision * 100:.1f} % | {t.cobertura * 100:.1f} % | {p.f1 * 100:.1f} % |"
        if r["bandit"]:
            b = cu[r["bandit"]].get(cl)
            fila += f" {b.f1 * 100:.1f} % |" if b and b.n else " sin regla |"
        L.append(fila)
    L += ["", "## Dónde falla TaintLens (por variante)", ""]
    if not r["fallos"]:
        L.append("Ningún fallo en este corpus.")
    else:
        L += ["| Variante | Fallos | Ejemplo |", "|---|---|---|"]
        for v, lst in sorted(r["fallos"].items(), key=lambda kv: -len(kv[1])):
            L.append(f"| {v} | {len(lst)} | {lst[0][0]} ({lst[0][1]}) |")
    L += ["", "## Detección por tipo de programa vulnerable", "", "| Variante | Programas | Detectados |", "|---|---|---|"]
    for k in sorted(x for x in cu["TaintLens"] if x.startswith("v:")):
        c = cu["TaintLens"][k]
        L.append(f"| {k[2:]} | {c.n} | {c.tp / c.n * 100:.1f} % |")
    L += ["", "## Falsas alarmas por tipo de programa seguro", "", "| Variante | Programas | Falsas alarmas |", "|---|---|---|"]
    for k in sorted(x for x in cu["TaintLens"] if x.startswith("s:")):
        c = cu["TaintLens"][k]
        L.append(f"| {k[2:]} | {c.n} | {c.fp} |")
    return "\n".join(L) + "\n"


def ejecutar(n: int = 600, semilla: int = 1, salida: str | None = None, como_json: bool = False) -> int:
    print(f"Generando y analizando {n * len(CLASES_BENCH)} programas (puede tardar un poco)...", file=sys.stderr)
    r = medir(n, semilla)
    if como_json:
        plano = {k: v for k, v in r.items() if k not in ("cuentas", "fallos", "comun")}
        plano["cuentas"] = {h: {k: c.a_dict() for k, c in d.items()} for h, d in r["cuentas"].items()}
        plano["fallos"] = {k: len(v) for k, v in r["fallos"].items()}
        texto = json.dumps(plano, ensure_ascii=False, indent=2)
    else:
        texto = informe_md(r)
    if salida:
        with open(salida, "w", encoding="utf-8") as f:
            f.write(texto)
        print(f"Informe guardado en {salida}", file=sys.stderr)
    else:
        sys.stdout.write(texto)
    return 0
