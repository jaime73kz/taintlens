
import pytest

from taintlens import supresion
from taintlens.analisis import escanear
from taintlens.config import Config, ErrorConfig, cargar, desde_dict
from conftest import clases, hallazgos, ids

TOML_BASE = """
[taintlens]
excluir = ["gen"]
severidad_minima = "media"
fallar_en = "critica"
reglas_desactivadas = ["TL113"]
estricto = true
"""


def _toml(texto):
    import tomllib
    return desde_dict(tomllib.loads(texto))


def test_config_basica():
    c = _toml(TOML_BASE)
    assert c.excluir == ["gen"] and c.severidad_minima == "media" and c.fallar_en == "critica"
    assert c.estricto and "TL113" in c.reglas_desactivadas


@pytest.mark.parametrize("texto,fragmento", [
    ('[taintlens]\nseveridad_minima = "enorme"', "severidad_minima"),
    ('[taintlens]\nexcluir = "gen"', "lista"),
    ('[taintlens]\nmagia = true', "desconocidas"),
    ('[taintlens]\nestricto = "si"', "true o false"),
    ('[taintlens]\nconfianza_minima = "total"', "confianza_minima"),
    ('[[fuente]]\ntipo = "marte"\nnombre = "x.y"', "tipo"),
    ('[[fuente]]\ntipo = "http"', "nombre"),
    ('[[sumidero]]\nclase = "inventada"\nnombre = "x.y"', "clase"),
    ('[[sumidero]]\nclase = "sql"\nnombre = "x.y"\nargs = ["a"]', "args"),
    ('[[saneador]]\nnombre = "x"\nclases = ["nada"]', "clase desconocida"),
])
def test_config_errores_claros(texto, fragmento):
    with pytest.raises(ErrorConfig) as e:
        _toml(texto)
    assert fragmento in str(e.value)


def test_fuente_personalizada():
    cfg = _toml('[[fuente]]\ntipo = "http"\nnombre = "miapp.leer_cuerpo"\n')
    src = "import os\nfrom miapp import leer_cuerpo\ndef f():\n    os.system(leer_cuerpo())\n"
    assert "cmd" not in clases(src)
    assert "cmd" in clases(src, config=cfg)


def test_sumidero_personalizado():
    cfg = _toml('[[sumidero]]\nclase = "sql"\nnombre = "miapp.ejecutar"\nargs = [0]\n')
    src = "from flask import request\nimport miapp\ndef f():\n    miapp.ejecutar(request.args['q'])\n"
    assert "sql" not in clases(src)
    assert "sql" in clases(src, config=cfg)


def test_saneador_personalizado():
    cfg = _toml('[[saneador]]\nnombre = "miapp.limpiar"\nclases = ["cmd"]\n')
    src = "import os, miapp\nfrom flask import request\ndef f():\n    os.system('x ' + miapp.limpiar(request.args['q']))\n"
    assert "cmd" in clases(src)
    assert "cmd" not in clases(src, config=cfg)


def test_saneador_todo():
    cfg = _toml('[[saneador]]\nnombre = "miapp.limpiar"\nclases = "todo"\n')
    src = "import os, miapp\nfrom flask import request\ndef f():\n    os.system('x ' + miapp.limpiar(request.args['q']))\n"
    assert not {h.clase for h in hallazgos(src, config=cfg) if h.clase == "cmd"}


def test_regla_desactivada_por_id_o_clase():
    src = "import os\nfrom flask import request\nos.system(request.args['c'])\n"
    assert "TL101" in ids(src)
    assert "TL101" not in ids(src, config=Config(reglas_desactivadas={"TL101"}))
    assert "TL101" not in ids(src, config=Config(reglas_desactivadas={"cmd"}))


def test_severidad_minima_filtra():
    src = "import os, sys\nos.system(sys.argv[1])\nimport hashlib\nhashlib.md5(b'x')\n"
    assert "TL205" in ids(src)
    assert "TL205" not in ids(src, config=Config(severidad_minima="media"))


def test_confianza_minima_filtra():
    src = "import os, extlib\nfrom flask import request\nos.system(extlib.f(request.args['x']))\n"
    assert "TL101" in ids(src)
    assert "TL101" not in ids(src, config=Config(confianza_minima="alta"))


def test_cargar_desde_archivo(tmp_path):
    (tmp_path / "taintlens.toml").write_text(TOML_BASE, encoding="utf-8")
    assert cargar(None, str(tmp_path)).severidad_minima == "media"


def test_cargar_desde_pyproject(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[tool.taintlens]\nfallar_en = "media"\n'
                                             '[[tool.taintlens.fuente]]\ntipo = "http"\nnombre = "a.b"\n', encoding="utf-8")
    c = cargar(None, str(tmp_path))
    assert c.fallar_en == "media" and len(c.fuentes) == 1


def test_pyproject_sin_seccion_se_ignora(tmp_path):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "x"\n', encoding="utf-8")
    assert cargar(None, str(tmp_path)).fallar_en == "alta"


def test_cargar_toml_roto(tmp_path):
    (tmp_path / "taintlens.toml").write_text("[taintlens\n", encoding="utf-8")
    with pytest.raises(ErrorConfig):
        cargar(None, str(tmp_path))


def test_cargar_ruta_inexistente():
    with pytest.raises(ErrorConfig):
        cargar("/no/existe.toml")


def test_sin_config_valores_por_defecto(tmp_path):
    c = cargar(None, str(tmp_path))
    assert c.fallar_en == "alta" and not c.estricto


# ----------------------------------------------------------------------------- supresiones
SRC = "import os\nfrom flask import request\ndef f():\n    os.system(request.args['c'])%s\n"


def test_ignore_en_la_linea():
    assert "TL101" in ids(SRC % "")
    assert "TL101" not in ids(SRC % "  # taintlens: ignore")


def test_ignore_con_regla_concreta():
    assert "TL101" not in ids(SRC % "  # taintlens: ignore[TL101]")
    assert "TL101" in ids(SRC % "  # taintlens: ignore[TL104]")
    assert "TL101" not in ids(SRC % "  # taintlens: ignore[TL104, TL101]")


def test_ignore_en_linea_anterior():
    src = "import os\nfrom flask import request\ndef f():\n    # taintlens: ignore[TL101]\n    os.system(request.args['c'])\n"
    assert "TL101" not in ids(src)


def test_ignore_no_afecta_a_otra_linea():
    src = ("import os\nfrom flask import request\ndef f():\n    x = 1  # taintlens: ignore\n"
           "    y = 2\n    os.system(request.args['c'])\n")
    assert "TL101" in ids(src)


def test_ignore_file():
    assert "TL101" not in ids("# taintlens: ignore-file\n" + SRC % "")


def test_nosec_compatible():
    assert "TL101" not in ids(SRC % "  # nosec")


def test_suprimidos_se_cuentan():
    r = escanear(fuentes={"a.py": SRC % "  # taintlens: ignore"})
    assert len(r.suprimidos) >= 1


def test_ignore_en_sumidero_multilinea():
    src = ("import os\nfrom flask import request\ndef f():\n    os.system(\n        request.args['c']  # taintlens: ignore\n    )\n")
    assert "TL101" not in ids(src)


# ----------------------------------------------------------------------------- baseline
def test_baseline_ciclo_completo(tmp_path):
    r = escanear(fuentes={"a.py": SRC % ""})
    ruta = str(tmp_path / "base.json")
    n = supresion.guardar_baseline(ruta, r.hallazgos)
    assert n >= 1
    huellas = supresion.cargar_baseline(ruta)
    r2 = escanear(fuentes={"a.py": SRC % ""}, baseline=huellas)
    assert not [h for h in r2.hallazgos if h.regla == "TL101"] and r2.en_baseline >= 1


def test_baseline_estable_si_se_mueve_el_codigo():
    a = escanear(fuentes={"a.py": SRC % ""}).hallazgos
    b = escanear(fuentes={"a.py": "# comentario\n# otro\n" + SRC % ""}).hallazgos
    assert {h.huella for h in a} == {h.huella for h in b}


def test_baseline_deja_pasar_lo_nuevo(tmp_path):
    r = escanear(fuentes={"a.py": SRC % ""})
    ruta = str(tmp_path / "b.json")
    supresion.guardar_baseline(ruta, r.hallazgos)
    nuevo = SRC % "" + "def g():\n    import pickle\n    pickle.loads(request.data)\n"
    r2 = escanear(fuentes={"a.py": nuevo}, baseline=supresion.cargar_baseline(ruta))
    assert "TL107" in {h.regla for h in r2.hallazgos} and "TL101" not in {h.regla for h in r2.hallazgos}


def test_baseline_errores(tmp_path):
    with pytest.raises(FileNotFoundError):
        supresion.cargar_baseline(str(tmp_path / "no.json"))
    (tmp_path / "mal.json").write_text("{no", encoding="utf-8")
    with pytest.raises(ValueError):
        supresion.cargar_baseline(str(tmp_path / "mal.json"))
    (tmp_path / "forma.json").write_text('{"x": 1}', encoding="utf-8")
    with pytest.raises(ValueError):
        supresion.cargar_baseline(str(tmp_path / "forma.json"))
