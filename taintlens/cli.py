"""Línea de comandos de TaintLens."""
from __future__ import annotations

import argparse
import os
import sys

from . import __version__, informes, supresion
from .analisis import escanear
from .catalogo import REGLAS
from .config import ErrorConfig, cargar
from .modelo import ORDEN_SEV, SEVERIDADES

COMANDOS = {"escanear", "reglas", "bench", "version"}


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="taintlens",
        description="TaintLens: análisis estático de flujo de datos para Python (defensivo).",
        epilog="Códigos de salida: 0 todo bien · 1 hay hallazgos del nivel pedido o superior · 2 error de uso.")
    sub = p.add_subparsers(dest="cmd")

    e = sub.add_parser("escanear", help="analiza archivos o carpetas")
    e.add_argument("rutas", nargs="*", default=["."], help="archivos o carpetas (por defecto, la actual)")
    e.add_argument("-f", "--formato", choices=["texto", "json", "sarif", "html", "md"], default="texto")
    e.add_argument("-o", "--salida", help="escribe el informe en este archivo")
    e.add_argument("-c", "--config", help="archivo de configuración TOML")
    e.add_argument("--severidad-minima", choices=SEVERIDADES, help="no muestra nada por debajo de este nivel")
    e.add_argument("--confianza-minima", choices=["baja", "media", "alta"])
    e.add_argument("--fallar-en", choices=list(SEVERIDADES) + ["nunca"],
                   help="devuelve código 1 si hay algo de este nivel o superior (por defecto, alta)")
    e.add_argument("--excluir", action="append", default=[], metavar="CARPETA", help="carpeta a ignorar (repetible)")
    e.add_argument("--sin-tests", action="store_true", help="ignora las carpetas tests/ y test/")
    e.add_argument("--regla-off", action="append", default=[], metavar="ID", help="desactiva una regla (TL104)")
    e.add_argument("--fuentes-archivo", action="store_true", help="trata el contenido de archivos como no confiable")
    e.add_argument("--estricto", action="store_true",
                   help="solo hallazgos donde el dato nunca pasó por funciones desconocidas")
    e.add_argument("--baseline", help="archivo de referencia: ignora lo que ya estaba")
    e.add_argument("--crear-baseline", metavar="ARCHIVO", help="guarda los hallazgos actuales como referencia y sale")
    e.add_argument("--sin-color", action="store_true")
    e.add_argument("--resumido", action="store_true", help="en texto, sin recorrido ni consejos")

    r = sub.add_parser("reglas", help="lista las reglas o explica una")
    r.add_argument("id", nargs="?", help="por ejemplo TL104")

    b = sub.add_parser("bench", help="mide la precisión sobre programas generados")
    b.add_argument("-n", "--n", type=int, default=600, help="programas por pareja (por defecto 600)")
    b.add_argument("--semilla", type=int, default=1)
    b.add_argument("--salida", help="guarda el informe en Markdown")
    b.add_argument("--json", action="store_true", help="salida en JSON")
    sub.add_parser("version", help="muestra la versión")
    return p


def _fuerza_utf8() -> None:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv=None) -> int:
    _fuerza_utf8()
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        argv = ["escanear"]
    elif argv[0] not in COMANDOS and argv[0] not in ("-h", "--help", "--version"):
        argv = ["escanear"] + argv
    if argv[0] == "--version":
        argv = ["version"]
    p = _parser()
    try:
        a = p.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    if a.cmd == "version":
        print(f"TaintLens {__version__}")
        return 0
    if a.cmd == "reglas":
        return _reglas(a)
    if a.cmd == "bench":
        return _bench(a)
    return _escanear(a)


def _escanear(a) -> int:
    base = a.rutas[0] if a.rutas and os.path.isdir(a.rutas[0]) else "."
    try:
        cfg = cargar(a.config, base)
    except ErrorConfig as e:
        print(f"Error de configuración: {e}", file=sys.stderr)
        return 2
    cfg.excluir = list(cfg.excluir) + a.excluir
    if a.severidad_minima:
        cfg.severidad_minima = a.severidad_minima
    if a.confianza_minima:
        cfg.confianza_minima = a.confianza_minima
    if a.fallar_en:
        cfg.fallar_en = a.fallar_en
    if a.sin_tests:
        cfg.incluir_tests = False
    if a.fuentes_archivo:
        cfg.fuentes_archivo = True
    if a.estricto:
        cfg.estricto = True
    cfg.reglas_desactivadas |= {x.upper() for x in a.regla_off}
    for x in a.rutas:
        if not os.path.exists(x):
            print(f"Error: no existe «{x}».", file=sys.stderr)
            return 2
    huellas = None
    ruta_base = a.baseline or (cfg.baseline or None)
    if ruta_base and not a.crear_baseline:
        try:
            huellas = supresion.cargar_baseline(ruta_base)
        except (FileNotFoundError, ValueError) as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2
    res = escanear(a.rutas, cfg, baseline=huellas)
    if a.crear_baseline:
        n = supresion.guardar_baseline(a.crear_baseline, res.hallazgos)
        print(f"Referencia guardada en {a.crear_baseline} ({n} hallazgos).")
        return 0
    if a.formato == "texto":
        color = (not a.sin_color) and sys.stdout.isatty() and not os.environ.get("NO_COLOR") and not a.salida
        salida = informes.texto(res, color=color, detalle=not a.resumido)
    else:
        salida = informes.FORMATOS[a.formato](res)
    if a.salida:
        try:
            with open(a.salida, "w", encoding="utf-8") as f:
                f.write(salida)
        except OSError as e:
            print(f"Error: no se pudo escribir «{a.salida}»: {e.strerror}.", file=sys.stderr)
            return 2
        print(f"Informe guardado en {a.salida} ({len(res.hallazgos)} hallazgos).")
    else:
        sys.stdout.write(salida)
    if cfg.fallar_en != "nunca" and any(ORDEN_SEV[h.severidad] >= ORDEN_SEV[cfg.fallar_en] for h in res.hallazgos):
        return 1
    return 0


def _reglas(a) -> int:
    if a.id:
        clave = a.id.upper()
        r = next((x for x in REGLAS.values() if x.id == clave or x.clase == a.id.lower()), None)
        if r is None:
            print(f"No existe la regla «{a.id}». Prueba «taintlens reglas».", file=sys.stderr)
            return 2
        print(f"{r.id} · {r.titulo}\n{r.cwe} · {r.owasp} · gravedad base: {r.severidad}\n\n{r.descripcion}\n\n"
              f"Cómo arreglarlo: {r.remedio}\n\nMal:\n  " + r.malo.replace("\n", "\n  ") +
              "\n\nBien:\n  " + r.bueno.replace("\n", "\n  "))
        return 0
    for r in sorted(REGLAS.values(), key=lambda x: x.id):
        print(f"{r.id}  {r.severidad:<8} {r.cwe:<9} {r.titulo}")
    return 0


def _bench(a) -> int:
    from . import bench
    return bench.ejecutar(a.n, a.semilla, a.salida, a.json)


if __name__ == "__main__":
    sys.exit(main())
