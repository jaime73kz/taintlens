"""Salidas: texto de terminal, JSON, SARIF 2.1.0, HTML y Markdown."""
from __future__ import annotations

import html
import json

from . import __version__
from .catalogo import REGLAS

ETIQ_SEV = {"critica": "CRÍTICA", "alta": "ALTA", "media": "MEDIA", "baja": "BAJA", "info": "INFO"}
COLOR = {"critica": "\x1b[1;37;41m", "alta": "\x1b[1;31m", "media": "\x1b[1;33m", "baja": "\x1b[36m",
         "info": "\x1b[2m"}
RESET, NEGRITA, TENUE = "\x1b[0m", "\x1b[1m", "\x1b[2m"
NIVEL_SARIF = {"critica": "error", "alta": "error", "media": "warning", "baja": "note", "info": "note"}
SEG_SARIF = {"critica": "9.5", "alta": "8.0", "media": "5.5", "baja": "3.0", "info": "1.0"}
URL = "https://github.com/jaime73kz/taintlens"


def _ruta(h) -> str:
    return h.ruta.replace("\\", "/")


# ---------------------------------------------------------------- texto
def texto(res, color: bool = False, detalle: bool = True, max_pasos: int = 12) -> str:
    def c(cod, t):
        return f"{cod}{t}{RESET}" if color else t
    out = []
    lineas = f"{res.lineas:,}".replace(",", ".")
    out.append(c(NEGRITA, f"TaintLens {__version__}") +
               f" — {res.archivos} archivos, {lineas} líneas, {res.funciones} funciones, "
               f"{res.entradas} puntos de entrada — {res.segundos:.2f} s")
    out.append("")
    for h in res.hallazgos:
        out.append(f"{c(COLOR[h.severidad], ' ' + ETIQ_SEV[h.severidad] + ' ')} {c(NEGRITA, h.regla)} "
                   f"{h.titulo} ({h.cwe})  {_ruta(h)}:{h.linea}  [confianza {h.confianza}]")
        out.append(f"    {c(TENUE, '│')} {h.codigo}")
        out.append(f"    {c(TENUE, '│')} {h.mensaje}")
        if detalle and h.traza and len(h.traza) > 1:
            out.append(f"    {c(TENUE, '│')} Recorrido del dato:")
            pasos = h.traza
            if len(pasos) > max_pasos:
                pasos = pasos[: max_pasos // 2] + [None] + pasos[-(max_pasos // 2):]
            for i, p in enumerate(pasos, 1):
                if p is None:
                    out.append(f"    {c(TENUE, '│')}    …")
                    continue
                out.append(f"    {c(TENUE, '│')}   {c(TENUE, f'{_ruta_p(p)}:{p.linea}'):<{40 if not color else 52}} "
                           f"{p.texto}")
        if detalle:
            out.append(f"    {c(TENUE, '└')} Cómo arreglarlo: {h.remedio}")
        out.append("")
    out.append(_resumen_texto(res, c))
    for ruta, msg in res.errores:
        out.append(c(COLOR["media"], f"aviso: {ruta}: {msg}"))
    for ruta, msg in res.omitidos:
        out.append(c(TENUE, f"omitido: {ruta}: {msg}"))
    for l in res.limites:
        out.append(c(TENUE, f"límite: {l}"))
    return "\n".join(out).rstrip() + "\n"


def _ruta_p(p) -> str:
    return p.ruta.replace("\\", "/")


def _resumen_texto(res, c) -> str:
    n = len(res.hallazgos)
    if n == 0:
        base = c("\x1b[1;32m", "Sin hallazgos.")
    else:
        sev = res.por_severidad()
        partes = [f"{sev[s]} {ETIQ_SEV[s].lower()}" for s in ("critica", "alta", "media", "baja", "info") if sev[s]]
        base = c(NEGRITA, f"{n} hallazgo{'s' if n != 1 else ''}") + " (" + ", ".join(partes) + ")"
    extra = []
    if res.suprimidos:
        extra.append(f"{len(res.suprimidos)} silenciados con comentarios")
    if res.en_baseline:
        extra.append(f"{res.en_baseline} ya conocidos (referencia)")
    return base + (" · " + ", ".join(extra) if extra else "")


# ---------------------------------------------------------------- JSON
def a_json(res) -> str:
    d = {
        "herramienta": {"nombre": "TaintLens", "version": __version__},
        "resumen": {"hallazgos": len(res.hallazgos), "por_severidad": res.por_severidad(),
                    "silenciados": len(res.suprimidos), "en_referencia": res.en_baseline,
                    "archivos": res.archivos, "lineas": res.lineas, "funciones": res.funciones,
                    "puntos_de_entrada": res.entradas, "segundos": res.segundos},
        "hallazgos": [h.a_dict() for h in res.hallazgos],
        "errores": [{"ruta": r, "mensaje": m} for r, m in res.errores],
        "omitidos": [{"ruta": r, "motivo": m} for r, m in res.omitidos],
    }
    return json.dumps(d, ensure_ascii=False, indent=2) + "\n"


# ---------------------------------------------------------------- SARIF
def _loc(ruta: str, linea: int, col: int, snippet: str = "", mensaje: str = "") -> dict:
    region = {"startLine": max(1, linea), "startColumn": col + 1}
    if snippet:
        region["snippet"] = {"text": snippet}
    d = {"physicalLocation": {"artifactLocation": {"uri": ruta.replace("\\", "/"), "uriBaseId": "%SRCROOT%"},
                              "region": region}}
    if mensaje:
        d["message"] = {"text": mensaje}
    return d


def a_sarif(res) -> str:
    ids = sorted(REGLAS.values(), key=lambda r: r.id)
    indice = {r.id: i for i, r in enumerate(ids)}
    reglas = []
    for r in ids:
        reglas.append({
            "id": r.id, "name": r.titulo.replace(" ", "").replace("(", "").replace(")", "")[:60],
            "shortDescription": {"text": r.titulo},
            "fullDescription": {"text": r.descripcion},
            "help": {"text": f"{r.remedio}\n\nMal: {r.malo}\nBien: {r.bueno}",
                     "markdown": f"{r.remedio}\n\n**Mal**\n```python\n{r.malo}\n```\n**Bien**\n```python\n{r.bueno}\n```"},
            "defaultConfiguration": {"level": NIVEL_SARIF[r.severidad]},
            "properties": {"tags": ["security", r.cwe, r.owasp], "security-severity": SEG_SARIF[r.severidad],
                           "precision": "high" if r.clase in ("secreto", "tls", "debug", "jwt") else "medium"},
        })
    resultados = []
    for h in res.hallazgos:
        r = {"ruleId": h.regla, "ruleIndex": indice[h.regla], "level": NIVEL_SARIF[h.severidad],
             "message": {"text": h.mensaje},
             "locations": [_loc(h.ruta, h.linea, h.col, h.codigo)],
             "partialFingerprints": {"taintlens/v1": h.huella},
             "properties": {"confianza": h.confianza, "severidad": h.severidad, "security-severity":
                            SEG_SARIF[h.severidad]}}
        if h.traza and len(h.traza) > 1:
            r["codeFlows"] = [{"threadFlows": [{"locations": [
                {"location": _loc(p.ruta, p.linea, p.col, p.codigo, p.texto)} for p in h.traza]}]}]
        resultados.append(r)
    d = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
         "runs": [{"tool": {"driver": {"name": "TaintLens", "version": __version__, "informationUri": URL,
                                       "rules": reglas}},
                   "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
                   "results": resultados,
                   "invocations": [{"executionSuccessful": True,
                                    "toolExecutionNotifications": [
                                        {"level": "warning", "message": {"text": f"{r}: {m}"}}
                                        for r, m in res.errores]}]}]}
    return json.dumps(d, ensure_ascii=False, indent=2) + "\n"


# ---------------------------------------------------------------- Markdown
def a_markdown(res) -> str:
    sev = res.por_severidad()
    L = ["# Informe de TaintLens", "",
         f"- Archivos analizados: **{res.archivos}** ({res.lineas} líneas, {res.funciones} funciones, "
         f"{res.entradas} puntos de entrada)",
         f"- Hallazgos: **{len(res.hallazgos)}** "
         f"(crítica {sev['critica']}, alta {sev['alta']}, media {sev['media']}, baja {sev['baja']}, info {sev['info']})",
         f"- Silenciados con comentarios: {len(res.suprimidos)} · ya conocidos: {res.en_baseline}",
         f"- Tiempo: {res.segundos:.2f} s · TaintLens {__version__}", ""]
    if not res.hallazgos:
        L.append("Sin hallazgos.")
        return "\n".join(L) + "\n"
    L += ["| Gravedad | Regla | Dónde | Qué |", "|---|---|---|---|"]
    for h in res.hallazgos:
        L.append(f"| {ETIQ_SEV[h.severidad]} | {h.regla} | `{_ruta(h)}:{h.linea}` | {h.titulo} |")
    L.append("")
    for h in res.hallazgos:
        L += [f"## {h.regla} · {h.titulo}", "",
              f"**{ETIQ_SEV[h.severidad]}** · confianza {h.confianza} · {h.cwe} · {h.owasp}  ",
              f"`{_ruta(h)}:{h.linea}`", "", "```python", h.codigo, "```", "", h.mensaje, ""]
        if len(h.traza or []) > 1:
            L.append("Recorrido del dato:")
            L.append("")
            for i, p in enumerate(h.traza, 1):
                L.append(f"{i}. `{_ruta_p(p)}:{p.linea}` — {p.texto}")
            L.append("")
        L += [f"**Cómo arreglarlo:** {h.remedio}", ""]
    return "\n".join(L)


# ---------------------------------------------------------------- HTML
def a_html(res) -> str:
    e = html.escape
    sev = res.por_severidad()
    tarjetas = "".join(
        f'<div class="card {s}"><b>{sev[s]}</b><span>{ETIQ_SEV[s].lower()}</span></div>'
        for s in ("critica", "alta", "media", "baja", "info"))
    filas = []
    for i, h in enumerate(res.hallazgos):
        traza = ""
        if len(h.traza or []) > 1:
            items = "".join(
                f'<li><code>{e(_ruta_p(p))}:{p.linea}</code> <span>{e(p.texto)}</span>'
                f'<pre>{e(p.codigo)}</pre></li>' for p in h.traza)
            traza = f"<h4>Recorrido del dato</h4><ol class='traza'>{items}</ol>"
        filas.append(
            f'<details class="hall {h.severidad}" data-sev="{h.severidad}"><summary>'
            f'<span class="tag {h.severidad}">{ETIQ_SEV[h.severidad]}</span> <b>{e(h.regla)}</b> '
            f'{e(h.titulo)} <code>{e(_ruta(h))}:{h.linea}</code></summary>'
            f'<div class="cuerpo"><p class="meta">{e(h.cwe)} · {e(h.owasp)} · confianza {e(h.confianza)}</p>'
            f'<pre class="cod">{e(h.codigo)}</pre><p>{e(h.mensaje)}</p>{traza}'
            f'<p class="fix"><b>Cómo arreglarlo:</b> {e(h.remedio)}</p></div></details>')
    cuerpo = "\n".join(filas) if filas else '<p class="ok">Sin hallazgos.</p>'
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Informe de TaintLens</title>
<style>
:root{{--bg:#0f1420;--panel:#171e2e;--txt:#e6eaf2;--mut:#8b96ad;--bd:#26304a;--ac:#6aa9ff}}
@media(prefers-color-scheme:light){{:root{{--bg:#f5f7fb;--panel:#fff;--txt:#1b2333;--mut:#5b6679;--bd:#dde3ee;--ac:#2563eb}}}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--txt);font:15px/1.55 system-ui,sans-serif}}
main{{max-width:980px;margin:0 auto;padding:28px 18px 60px}}h1{{margin:0 0 4px;font-size:26px}}
.sub{{color:var(--mut);margin-bottom:20px}}.cards{{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}}
.card{{flex:1;min-width:96px;background:var(--panel);border:1px solid var(--bd);border-radius:10px;padding:12px;text-align:center}}
.card b{{display:block;font-size:26px}}.card span{{color:var(--mut);font-size:12px;text-transform:uppercase}}
.card.critica b{{color:#ff5d73}}.card.alta b{{color:#ff8a4c}}.card.media b{{color:#e5b53b}}.card.baja b{{color:#4cc2d6}}
.filtros{{margin:14px 0}}.filtros button{{background:var(--panel);color:var(--txt);border:1px solid var(--bd);
border-radius:999px;padding:5px 13px;margin-right:6px;cursor:pointer}}.filtros button.on{{border-color:var(--ac);color:var(--ac)}}
details.hall{{background:var(--panel);border:1px solid var(--bd);border-radius:10px;margin:10px 0;border-left:4px solid var(--mut)}}
details.critica{{border-left-color:#ff5d73}}details.alta{{border-left-color:#ff8a4c}}details.media{{border-left-color:#e5b53b}}
details.baja{{border-left-color:#4cc2d6}}summary{{padding:12px 14px;cursor:pointer}}.cuerpo{{padding:0 16px 14px}}
.tag{{font-size:11px;font-weight:700;border-radius:5px;padding:2px 7px;color:#fff;background:#6b7690}}
.tag.critica{{background:#d6334b}}.tag.alta{{background:#e0702f}}.tag.media{{background:#b58a14}}.tag.baja{{background:#2a93a6}}
code,pre{{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}}pre{{margin:4px 0;white-space:pre-wrap;word-break:break-word}}
.cod{{background:var(--bg);border:1px solid var(--bd);border-radius:8px;padding:8px 10px}}.meta{{color:var(--mut);font-size:13px}}
ol.traza{{padding-left:20px}}ol.traza li{{margin:6px 0}}ol.traza span{{color:var(--mut)}}ol.traza pre{{color:var(--mut)}}
.fix{{background:rgba(76,194,214,.08);border-radius:8px;padding:8px 10px}}.ok{{color:#3fb97a;font-weight:600}}
footer{{margin-top:30px;color:var(--mut);font-size:12px}}
</style></head><body><main>
<h1>Informe de TaintLens</h1>
<div class="sub">{res.archivos} archivos · {res.lineas} líneas · {res.funciones} funciones · {res.entradas} puntos de entrada · {res.segundos:.2f} s</div>
<div class="cards">{tarjetas}</div>
<div class="filtros" id="f"><button class="on" data-s="todas">Todas</button><button data-s="critica">Crítica</button>
<button data-s="alta">Alta</button><button data-s="media">Media</button><button data-s="baja">Baja</button></div>
{cuerpo}
<footer>Generado por TaintLens {e(__version__)}. Los hallazgos son avisos que hay que revisar: el análisis estático puede fallar en ambos sentidos.</footer>
</main>
<script>
document.querySelectorAll('#f button').forEach(function(b){{b.onclick=function(){{
document.querySelectorAll('#f button').forEach(function(x){{x.classList.remove('on')}});b.classList.add('on');
var s=b.dataset.s;document.querySelectorAll('details.hall').forEach(function(d){{d.style.display=(s==='todas'||d.dataset.sev===s)?'':'none'}})}}}});
</script></body></html>
"""


FORMATOS = {"json": a_json, "sarif": a_sarif, "md": a_markdown, "html": a_html}
