import json
import sys

import pytest

from taintlens import __version__, informes
from taintlens.analisis import escanear
from taintlens.cli import main

APP = """import os, sqlite3
from flask import Flask, request
app = Flask(__name__)
@app.route("/p")
def p():
    h = request.args.get("h", "")
    os.system("ping " + h)
    cur = sqlite3.connect("d").cursor()
    cur.execute(f"SELECT * FROM u WHERE n = '{h}'")
    return "<b>" + h + "</b>"
"""


@pytest.fixture
def res():
    return escanear(fuentes={"app.py": APP})


@pytest.fixture
def carpeta(tmp_path):
    (tmp_path / "app.py").write_text(APP, encoding="utf-8")
    return str(tmp_path)


# ----------------------------------------------------------------------------- informes
def test_texto_contiene_lo_esencial(res):
    t = informes.texto(res)
    assert "TL101" in t and "app.py:7" in t and "Recorrido del dato" in t and "Cómo arreglarlo" in t
    assert "\x1b[" not in t


def test_texto_con_color(res):
    assert "\x1b[" in informes.texto(res, color=True)


def test_texto_resumido(res):
    assert "Recorrido" not in informes.texto(res, detalle=False)


def test_texto_sin_hallazgos():
    assert "Sin hallazgos" in informes.texto(escanear(fuentes={"a.py": "x = 1\n"}))


def test_json_valido_y_completo(res):
    d = json.loads(informes.a_json(res))
    assert d["herramienta"]["version"] == __version__
    assert d["resumen"]["hallazgos"] == len(d["hallazgos"]) >= 3
    h = d["hallazgos"][0]
    assert {"regla", "cwe", "severidad", "confianza", "ruta", "linea", "traza", "huella", "remedio"} <= set(h)


def test_sarif_estructura(res):
    d = json.loads(informes.a_sarif(res))
    assert d["version"] == "2.1.0" and "$schema" in d
    run = d["runs"][0]
    assert run["tool"]["driver"]["name"] == "TaintLens"
    reglas = {r["id"]: i for i, r in enumerate(run["tool"]["driver"]["rules"])}
    assert len(reglas) >= 24
    for r in run["results"]:
        assert r["ruleId"] in reglas and run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"]
        assert r["level"] in ("error", "warning", "note")
        loc = r["locations"][0]["physicalLocation"]
        assert loc["region"]["startLine"] >= 1 and loc["region"]["startColumn"] >= 1
        assert "\\" not in loc["artifactLocation"]["uri"]
        assert r["partialFingerprints"]["taintlens/v1"]


def test_sarif_code_flows(res):
    d = json.loads(informes.a_sarif(res))
    con_flujo = [r for r in d["runs"][0]["results"] if "codeFlows" in r]
    assert con_flujo
    locs = con_flujo[0]["codeFlows"][0]["threadFlows"][0]["locations"]
    assert len(locs) >= 2 and all("message" in l["location"] for l in locs)


def test_sarif_reglas_con_ayuda_y_cwe():
    d = json.loads(informes.a_sarif(escanear(fuentes={"a.py": "x = 1\n"})))
    for r in d["runs"][0]["tool"]["driver"]["rules"]:
        assert r["help"]["text"] and r["properties"]["security-severity"] and any(
            t.startswith("CWE-") for t in r["properties"]["tags"])


def test_markdown(res):
    m = informes.a_markdown(res)
    assert m.startswith("# Informe") and "| Gravedad |" in m and "```python" in m


def test_html_autocontenido_y_escapado():
    src = "import os\nfrom flask import request\nos.system('<script>alert(1)</script>' + request.args['x'])\n"
    h = informes.a_html(escanear(fuentes={"a.py": src}))
    assert "<script>alert(1)</script>" not in h.split("<script>")[0]
    assert "&lt;script&gt;" in h and "http://" not in h.replace("https://github", "") and "<link" not in h


def test_html_sin_hallazgos():
    assert "Sin hallazgos" in informes.a_html(escanear(fuentes={"a.py": "x = 1\n"}))


def test_orden_de_gravedad(res):
    orden = {"critica": 4, "alta": 3, "media": 2, "baja": 1, "info": 0}
    sevs = [orden[h.severidad] for h in res.hallazgos]
    assert sevs == sorted(sevs, reverse=True)


# ----------------------------------------------------------------------------- CLI
def test_cli_codigo_de_salida_con_hallazgos(carpeta, capsys):
    assert main([carpeta, "--sin-color"]) == 1
    assert "TL101" in capsys.readouterr().out


def test_cli_limpio_sale_con_cero(tmp_path, capsys):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert main([str(tmp_path)]) == 0


def test_cli_fallar_en_nunca(carpeta):
    assert main([carpeta, "--fallar-en", "nunca"]) == 0


def test_cli_fallar_en_umbral(tmp_path):
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n", encoding="utf-8")
    assert main([str(tmp_path)]) == 0
    assert main([str(tmp_path), "--fallar-en", "baja"]) == 1


@pytest.mark.parametrize("fmt", ["json", "sarif", "html", "md"])
def test_cli_formatos_a_archivo(carpeta, tmp_path, fmt, capsys):
    salida = str(tmp_path / f"informe.{fmt}")
    assert main([carpeta, "-f", fmt, "-o", salida, "--fallar-en", "nunca"]) == 0
    contenido = open(salida, encoding="utf-8").read()
    assert contenido.strip()
    if fmt in ("json", "sarif"):
        json.loads(contenido)


def test_cli_json_por_stdout_es_json_puro(carpeta, capsys):
    main([carpeta, "-f", "json", "--fallar-en", "nunca"])
    json.loads(capsys.readouterr().out)


def test_cli_ruta_inexistente(capsys):
    assert main(["/no/existe/jamas"]) == 2
    assert "no existe" in capsys.readouterr().err


def test_cli_config_invalida(carpeta, tmp_path, capsys):
    cfg = tmp_path / "x.toml"
    cfg.write_text("[taintlens]\nmagia = 1\n", encoding="utf-8")
    assert main([carpeta, "-c", str(cfg)]) == 2
    assert "configuración" in capsys.readouterr().err.lower()


def test_cli_regla_off(carpeta, capsys):
    main([carpeta, "--regla-off", "TL101", "--sin-color", "--fallar-en", "nunca"])
    assert "TL101" not in capsys.readouterr().out


def test_cli_severidad_minima(carpeta, capsys):
    main([carpeta, "--severidad-minima", "critica", "--sin-color", "--fallar-en", "nunca"])
    salida = capsys.readouterr().out
    assert "TL101" in salida and "TL108" not in salida


def test_cli_baseline_ciclo(carpeta, tmp_path, capsys):
    base = str(tmp_path / "b.json")
    assert main([carpeta, "--crear-baseline", base]) == 0
    assert main([carpeta, "--baseline", base]) == 0


def test_cli_baseline_inexistente(carpeta, capsys):
    assert main([carpeta, "--baseline", "/no/hay.json"]) == 2


def test_cli_reglas_lista_y_detalle(capsys):
    assert main(["reglas"]) == 0
    assert "TL101" in capsys.readouterr().out
    assert main(["reglas", "TL104"]) == 0
    assert "SQL" in capsys.readouterr().out
    assert main(["reglas", "TL999"]) == 2


def test_cli_version(capsys):
    assert main(["version"]) == 0 and __version__ in capsys.readouterr().out
    assert main(["--version"]) == 0


def test_cli_sin_argumentos_escanea_carpeta_actual(tmp_path, monkeypatch, capsys):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    assert main([]) == 0


def test_cli_ruta_como_primer_argumento_implicito(carpeta, capsys):
    assert main([carpeta, "--sin-color"]) == 1


def test_cli_salida_no_escribible(carpeta, capsys):
    assert main([carpeta, "-o", "/no/existe/dir/x.txt"]) == 2


def test_cli_archivo_con_error_de_sintaxis_no_rompe(tmp_path, capsys):
    (tmp_path / "mal.py").write_text("def (:\n", encoding="utf-8")
    (tmp_path / "bien.py").write_text("x = 1\n", encoding="utf-8")
    assert main([str(tmp_path), "--sin-color"]) == 0
    assert "sintaxis" in capsys.readouterr().out


def test_cli_modulo_ejecutable(carpeta):
    import subprocess
    r = subprocess.run([sys.executable, "-m", "taintlens", carpeta, "--sin-color", "-f", "json"],
                       capture_output=True, text=True, cwd=str(__import__("pathlib").Path(__file__).parent.parent))
    assert r.returncode == 1
    json.loads(r.stdout)
