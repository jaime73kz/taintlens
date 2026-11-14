import ast
import os
import random
import sysconfig

import pytest

from taintlens import bench
from taintlens.analisis import escanear
from taintlens.corpus import CASOS
from taintlens.generador import CLASES_BENCH, generar_corpus
from conftest import ids


# ----------------------------------------------------------------------------- generador
def test_generador_produce_python_valido():
    for c in generar_corpus(40, 7):
        ast.parse(c.codigo)


def test_generador_es_determinista():
    a = [c.codigo for c in generar_corpus(10, 3)]
    b = [c.codigo for c in generar_corpus(10, 3)]
    c = [c.codigo for c in generar_corpus(10, 4)]
    assert a == b and a != c


def test_generador_equilibrado():
    cs = generar_corpus(20, 1)
    assert abs(sum(c.vulnerable for c in cs) - len(cs) / 2) <= len(CLASES_BENCH)
    assert {c.clase for c in cs} == set(CLASES_BENCH)


# ----------------------------------------------------------------------------- banco de pruebas
def test_bench_taintlens_supera_con_mucho_a_los_patrones():
    r = bench.medir(60, semilla=11, con_bandit=False)
    tl = r["cuentas"]["TaintLens"]["__total__"]
    pat = r["cuentas"]["Patrones (sin flujo)"]["__total__"]
    assert tl.f1 >= 0.95, r["fallos"]
    assert tl.precision >= 0.95 and tl.cobertura >= 0.95
    assert pat.f1 < tl.f1 - 0.15


def test_bench_informe_markdown_se_genera():
    r = bench.medir(10, semilla=2, con_bandit=False)
    md = bench.informe_md(r)
    assert "Resultado global" in md and "Lee esto antes de fiarte" in md


# ----------------------------------------------------------------------------- corpus manual
@pytest.mark.parametrize("caso", [c for c in CASOS if not c.limitacion], ids=lambda c: c.id)
def test_corpus_manual(caso):
    clases = {h.clase for h in escanear(fuentes=caso.fuentes).hallazgos}
    for clase, esperado in caso.espera.items():
        assert (clase in clases) == esperado, f"{caso.id}: {clase} esperado={esperado}, obtenido={sorted(clases)}"


@pytest.mark.parametrize("caso", [c for c in CASOS if c.limitacion], ids=lambda c: c.id)
def test_limitaciones_conocidas_siguen_siendolo(caso):
    """Si alguna de estas pasa a funcionar, hay que actualizar docs/DISENO.md y mover el caso."""
    clases = {h.clase for h in escanear(fuentes=caso.fuentes).hallazgos}
    todo_bien = all((clase in clases) == esperado for clase, esperado in caso.espera.items())
    assert not todo_bien, f"{caso.id} ya funciona: actualiza la documentación de limitaciones"


def test_corpus_manual_tiene_tamano_razonable():
    assert len(CASOS) >= 55 and sum(c.limitacion for c in CASOS) >= 3
    assert len({c.id for c in CASOS}) == len(CASOS)


# ----------------------------------------------------------------------------- robustez
def test_archivo_vacio():
    assert ids("") == set()


def test_solo_comentarios_y_unicode():
    assert ids("# ñandú 日本語 😀\nx = 'ñ'\n") == set()


def test_anidamiento_profundo_no_rompe():
    src = "import os\nfrom flask import request\nv = request.args['x']\nw = " + " + ".join(["v"] * 1500) + "\nos.system(w)\n"
    assert "TL101" in ids(src)


def test_parentesis_muy_anidados_no_rompen():
    src = "x = " + "(" * 150 + "1" + ")" * 150 + "\n"
    ids(src)


def test_funcion_con_miles_de_sentencias():
    cuerpo = "\n".join(f"    v{i} = v{i - 1} + 'a'" for i in range(1, 3000))
    src = "import os\nfrom flask import request\ndef f():\n    v0 = request.args['x']\n" + cuerpo + "\n    os.system(v2999)\n"
    assert "TL101" in ids(src)


def test_bucles_anidados_profundos_terminan():
    src = "import os\nfrom flask import request\ndef f():\n    v = request.args['x']\n"
    for i in range(12):
        src += "    " * (i + 1) + f"for a{i} in range(3):\n"
    src += "    " * 13 + "v = v + 'a'\n" + "    " * 13 + "os.system(v)\n"
    assert "TL101" in ids(src)


def test_muchas_clases_y_herencia_larga():
    src = "class C0:\n    def m(self, x):\n        return x\n"
    for i in range(1, 60):
        src += f"class C{i}(C{i - 1}):\n    pass\n"
    ids(src)


def test_determinismo_del_resultado():
    app = "import os\nfrom flask import request\ndef f():\n    os.system(request.args['a'])\n    os.system(request.args['b'])\n"
    a = [(h.regla, h.linea, h.huella) for h in escanear(fuentes={"a.py": app}).hallazgos]
    for _ in range(3):
        assert [(h.regla, h.linea, h.huella) for h in escanear(fuentes={"a.py": app}).hallazgos] == a


def test_sin_efectos_laterales_sobre_el_codigo_analizado(tmp_path):
    marca = tmp_path / "creado.txt"
    (tmp_path / "a.py").write_text(f"open({str(marca)!r}, 'w').write('x')\nimport os\nos.system('touch {marca}')\n", encoding="utf-8")
    escanear([str(tmp_path)])
    assert not marca.exists()


@pytest.mark.skipif(not os.path.isdir(sysconfig.get_paths()["stdlib"]), reason="sin biblioteca estándar")
def test_biblioteca_estandar_no_rompe_el_analizador():
    std = sysconfig.get_paths()["stdlib"]
    archivos = sorted(f for f in os.listdir(std) if f.endswith(".py"))
    random.Random(5).shuffle(archivos)
    fuentes = {}
    for f in archivos[:60]:
        try:
            fuentes[f] = open(os.path.join(std, f), encoding="utf-8").read()
        except (OSError, UnicodeDecodeError):
            pass
    r = escanear(fuentes=fuentes)
    assert r.archivos >= 40 and r.funciones > 100 and not r.limites


def test_autoescaneo_sin_hallazgos_graves():
    raiz = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "taintlens")
    r = escanear([raiz])
    graves = [h for h in r.hallazgos if h.severidad in ("critica", "alta")]
    assert not graves, [(h.regla, h.ruta, h.linea) for h in graves]
