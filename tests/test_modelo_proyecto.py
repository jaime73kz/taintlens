

from taintlens.modelo import Paso, Taint, Taints, VACIO, bajar
from taintlens.proyecto import Proyecto


def paso(l=1, t="x"):
    return Paso("a.py", l, 0, "codigo", t)


def test_taint_con_paso_no_duplica_la_misma_linea():
    t = Taint("http", paso()).con_paso(paso(2, "a"))
    assert t.con_paso(paso(2, "a")) is t


def test_taint_pasos_limitados():
    t = Taint("http", paso())
    for i in range(100):
        t = t.con_paso(paso(i + 10, f"p{i}"))
    assert len(t.pasos) <= 16


def test_limpiar_acumula_clases():
    t = Taint("http", paso()).limpiar({"cmd"}).limpiar({"xss"})
    assert t.limpio == {"cmd", "xss"}


def test_taints_union_conserva_el_recorrido_mas_corto():
    corto = Taint("http", paso())
    largo = corto.con_paso(paso(5)).con_paso(paso(6))
    assert len(Taints([largo]).union(Taints([corto]))) == 1
    assert list(Taints([largo]).union(Taints([corto])))[0].pasos == ()


def test_taints_distintas_clases_limpias_son_distintos():
    t = Taint("http", paso())
    assert len(Taints([t, t.limpiar({"cmd"})])) == 2


def test_vacio_es_falso_y_union_neutra():
    t = Taints([Taint("http", paso())])
    assert not VACIO and t.union(VACIO) is t and VACIO.union(t) is t


def test_simbolico():
    assert Taint("param:0", paso()).simbolico and not Taint("http", paso()).simbolico


def test_bajar_severidad():
    assert bajar("critica") == "alta" and bajar("critica", 2) == "media" and bajar("info") == "info"


# ----------------------------------------------------------------------------- proyecto
def test_desde_fuentes_nombres_de_modulo():
    p = Proyecto.desde_fuentes({"pkg/__init__.py": "", "pkg/a.py": "x = 1", "b.py": "y = 2"})
    assert set(p.modulos) == {"pkg", "pkg.a", "b"}


def test_funciones_y_metodos_indexados():
    p = Proyecto.desde_fuentes({"a.py": "def f(x, *a, k=1, **kw):\n    pass\nclass C:\n    def m(self):\n        def i():\n            pass\n"})
    assert "a:f" in p.funcs and "a:C.m" in p.funcs and "a:C.m.i" in p.funcs
    f = p.funcs["a:f"]
    assert f.params == ["x", "k"] and f.vararg == "a" and f.kwarg == "kw"
    assert p.funcs["a:C.m"].clase == "a:C" and p.funcs["a:C.m.i"].clase is None


def test_imports_relativos_se_resuelven():
    p = Proyecto.desde_fuentes({"pkg/__init__.py": "", "pkg/a.py": "from .b import f\nfrom . import c\nfrom .. import z\n",
                                "pkg/b.py": "def f(): pass", "pkg/c.py": ""})
    im = p.modulos["pkg.a"].imports
    assert im["f"] == "pkg.b.f" and im["c"] == "pkg.c"


def test_mro_con_herencia_entre_modulos():
    p = Proyecto.desde_fuentes({"a.py": "class A:\n    def m(self): pass\n",
                                "b.py": "from a import A\nclass B(A):\n    pass\n"})
    assert [c.nombre for c in p.mro("b:B")] == ["B", "A"]
    assert p.metodo("b:B", "m").id == "a:A.m"


def test_mro_con_ciclo_termina():
    p = Proyecto.desde_fuentes({"a.py": "class A(B):\n    pass\nclass B(A):\n    pass\n"})
    assert len(p.mro("a:A")) == 2


def test_error_de_sintaxis_se_registra_y_no_rompe():
    p = Proyecto.desde_fuentes({"mal.py": "def (:\n", "bien.py": "x = 1\n"})
    assert "bien" in p.modulos and p.errores and p.errores[0][0] == "mal.py"


def test_cargar_carpeta_ignora_excluidas(proyecto_tmp):
    d = proyecto_tmp({"a.py": "x=1", ".venv/lib/b.py": "y=1", "node_modules/c.py": "z=1", "src/d.py": "w=1"})
    p = Proyecto.cargar([d])
    assert {m.ruta.rsplit("/", 1)[-1] for m in p.modulos.values()} == {"a.py", "d.py"}


def test_cargar_excluir_personalizado(proyecto_tmp):
    d = proyecto_tmp({"a.py": "x=1", "gen/b.py": "y=1"})
    assert len(Proyecto.cargar([d], excluir=["gen"]).modulos) == 1


def test_cargar_sin_tests(proyecto_tmp):
    d = proyecto_tmp({"a.py": "x=1", "tests/t.py": "y=1"})
    assert len(Proyecto.cargar([d], incluir_tests=False).modulos) == 1


def test_cargar_archivo_binario_se_omite(proyecto_tmp):
    d = proyecto_tmp({"b.py": b"\x00\x01\x02def f(): pass"})
    p = Proyecto.cargar([d])
    assert not p.modulos and p.omitidos


def test_cargar_codificacion_rara_no_rompe(proyecto_tmp):
    d = proyecto_tmp({"l.py": b"# -*- coding: latin-1 -*-\nx = '\xe9\xe8'\n"})
    assert Proyecto.cargar([d]).modulos


def test_cargar_ruta_inexistente():
    p = Proyecto.cargar(["/no/existe/nunca"])
    assert p.errores


def test_cargar_archivo_enorme_se_omite(proyecto_tmp):
    d = proyecto_tmp({"g.py": "x = 1\n" * 500_000})
    assert Proyecto.cargar([d]).omitidos


def test_nombres_repetidos_no_se_pisan():
    p = Proyecto.desde_fuentes({"a/main.py": "x = 1", "b/main.py": "y = 2"})
    assert len(p.modulos) == 2
