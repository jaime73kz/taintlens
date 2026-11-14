# TaintLens

**Análisis estático de flujo de datos para Python.** Sigue cada dato que controla un atacante desde donde entra (una petición web, un argumento que elige un modelo de lenguaje, una variable de entorno) hasta donde hace daño (un comando, una consulta SQL, un `exec`, un archivo), a través de variables, funciones, clases y archivos distintos, y entiende cuándo alguien lo ha saneado de verdad.

Es una herramienta **defensiva**: encuentra fallos en tu código para que los arregles. No ataca nada ni ejecuta el código que analiza.

```text
 CRÍTICA  TL101 Inyección de comandos del sistema (CWE-78)  utils.py:7  [confianza alta]
    │ return subprocess.run("ping -c 1 " + host, shell=True, capture_output=True, text=True).stdout
    │ Entrada HTTP (línea 21) llega sin sanear a comando con shell=True en utils.py:7.
    │ Recorrido del dato:
    │   app.py:21     entrada HTTP: request
    │   app.py:21     llamada a comprobar_servidor()
    │   utils.py:7    sumidero (comando con shell=True): subprocess.run
    └ Cómo arreglarlo: usa subprocess con una lista de argumentos y sin shell=True ...
```

El dato entra en `app.py` y el fallo está en `utils.py`: un buscador de patrones solo vería un `subprocess.run` con `shell=True`; TaintLens sabe que llega ahí desde internet.

## Por qué no es «otro grep con regex»

| | Buscador de patrones | TaintLens |
|---|---|---|
| ¿El argumento es una constante? | No distingue | Sí: `os.system("ls")` no avisa |
| `shlex.quote(x)` antes del sumidero | Avisa igual | No avisa |
| `html.escape(x)` antes de `os.system` | No lo evalúa | **Sí avisa**: ese saneador no protege contra comandos |
| `if x not in PERMITIDOS: return` | No lo ve | Entiende que después de eso `x` está acotado |
| El dato pasa por 3 funciones y 2 archivos | No lo sigue | Lo sigue y te enseña el recorrido |
| Campo de una clase rellenado en `__init__` | No lo sigue | Lo sigue |
| Herramienta de un agente (`@mcp.tool()`) | No sabe que es una entrada | Sus argumentos los elige el modelo: los trata como no confiables |

## Qué detecta

**14 clases con seguimiento del dato** (TL101–TL114): inyección de comandos y de argumentos, de código, SQL, recorrido de rutas, SSRF, deserialización insegura, XSS, plantillas (SSTI), redirección abierta, XXE, ReDoS, inyección en registros y **entrada no confiable en el prompt de un modelo**.

**10 reglas de forma** (TL201–TL210): secretos en el código, TLS desactivado, `debug=True`, JWT sin verificar, hashes débiles, `yaml.load` sin cargador seguro, `shell=True` con comando dinámico, `mktemp`, permisos `0o777` y `trust_remote_code=True`.

Pensado también para código de **aplicaciones con IA**: la salida de un modelo se trata como una fuente no confiable (`exec(respuesta)` es un fallo), los argumentos de las herramientas MCP / function-calling vienen de un tercero, y lo que se mete en un prompt puede ser una inyección de instrucciones.

Cada regla lleva su CWE, su categoría OWASP, un ejemplo del fallo y de la corrección: `taintlens reglas TL104`.

## Uso en 30 segundos

```bash
pip install -e .                       # no necesita ninguna dependencia
taintlens escanear mi_proyecto/        # informe en la terminal
taintlens escanear . -f html -o informe.html
taintlens escanear . -f sarif -o resultados.sarif    # para GitHub Code Scanning
taintlens escanear . --fallar-en alta  # código de salida 1 si hay algo grave (para CI)
```

Pruébalo con las apps de ejemplo:

```bash
taintlens escanear examples/app_vulnerable   # 16 hallazgos
taintlens escanear examples/app_corregida    # 0 (y uno silenciado a propósito, con su explicación)
```

Guía paso a paso: [docs/TUTORIAL.md](docs/TUTORIAL.md).

## Salidas

Terminal (con color), **JSON**, **SARIF 2.1.0** (con el recorrido completo como `codeFlows`: GitHub lo muestra paso a paso), **HTML** autocontenido con filtros y **Markdown**. En [examples/ci/](examples/ci/) hay un flujo de GitHub Actions y un hook de pre-commit.

Para adoptarlo en un proyecto que ya tiene deuda: `--crear-baseline referencia.json` guarda lo existente y `--baseline referencia.json` solo avisa de lo **nuevo**. Para casos concretos, `# taintlens: ignore[TL104]` en la línea. Y un `taintlens.toml` permite añadir tus propias fuentes, sumideros y saneadores ([ejemplo](examples/taintlens.toml)).

## Resultados medidos (y sus límites)

Cifras reales, reproducibles con `taintlens bench` y `python -m pytest`:

**Banco de pruebas generado** ([docs/BENCH.md](docs/BENCH.md)): 5.400 programas (2.700 vulnerables y 2.700 seguros, 9 clases, con cadenas de transformaciones, funciones auxiliares, clases, saneadores correctos, saneadores equivocados, señuelos y guardas que no cortan el flujo).

| Herramienta | Precisión | Cobertura | F1 |
|---|---|---|---|
| **TaintLens** | 100 % | 100 % | 100 % |
| Escáner de patrones (el mismo catálogo, sin flujo) | 52,5 % | 100 % | 68,9 % |
| Bandit 1.9.4, solo clases donde tiene reglas | 54,9 % | 80,7 % | 65,4 % |

**Léelo con cabeza.** Ese corpus lo generé yo con las mismas ideas con las que diseñé el motor, así que el 100 % mide que es coherente y robusto con muchas formas de escribir lo mismo, **no** que encuentre el 100 % de los fallos de un proyecto cualquiera. Lo que sí enseña la comparación es la diferencia entre mirar patrones y seguir el dato: un buscador sin flujo marca la mitad de los programas seguros.

**Corpus escrito a mano** (56 casos con estilos reales: Django, FastAPI, Flask, MCP, LangChain/OpenAI, AWS Lambda, Streamlit, varios módulos, herencia…): los 56 salen como se espera. Además hay **4 limitaciones conocidas** que fallan a propósito y están documentadas ([docs/DISENO.md](docs/DISENO.md)); un test comprueba que siguen fallando, así que la documentación no puede desfasarse sin que salte.

**Código ajeno**: sobre la biblioteca estándar de Python (538 archivos, 278.000 líneas, 13.000 funciones) analiza sin romperse en 32 s. Sus únicos 6 hallazgos de gravedad crítica son todos de `logging.config`, que hace `eval` de configuración recibida por un socket (un riesgo del que avisa la propia documentación de Python); el resto son de gravedad media o baja, casi todos por entradas locales (línea de comandos, entorno). Sobre 3,6 millones de líneas de todo un entorno Python no se cae.

**Pruebas**: 409 tests (cada construcción del lenguaje, cada saneador, cada guarda, interprocedural, recursión, varios módulos, formatos de salida, CLI, robustez con código muy anidado, determinismo y un autoescaneo del propio TaintLens).

## Cómo funciona (resumen)

1. Carga todos los archivos, resuelve imports (incluidos los relativos), clases y herencia.
2. Para cada función calcula un **resumen** con parámetros simbólicos: qué devuelve según lo que le pasen, a qué sumideros llegan sus parámetros, qué campos de objeto escribe.
3. Repite hasta que los resúmenes dejan de cambiar (punto fijo; funciona con recursión).
4. En la pasada final sustituye los símbolos por los datos reales de cada llamada y genera los hallazgos con su recorrido.

Cada dato lleva anotadas las clases de fallo que ya han sido neutralizadas (`shlex.quote` neutraliza comandos, no XSS), y las guardas (`if x not in OK: return`) se entienden en el flujo de control. Todo el diseño, con sus decisiones y límites, en [docs/DISENO.md](docs/DISENO.md).

## Límites (en serio)

Es un análisis estático: puede fallar en los dos sentidos. No sigue `getattr` dinámico, funciones guardadas en objetos (`functools.partial`), ni datos que viajan por una base de datos y vuelven (XSS almacenado); los campos de objeto se siguen por clase, no por instancia; y las llamadas a bibliotecas que no conoce las trata como «el dato pasa» con menos confianza. Solo analiza Python. Lista completa y razonada en [docs/DISENO.md](docs/DISENO.md#limites-conocidos).

Trátalo como un revisor muy rápido y metódico, no como un juez: cada aviso trae el recorrido para que lo compruebes en un minuto.

## Estructura

```
taintlens/
  modelo.py       datos contaminados, pasos, hallazgos
  catalogo.py     reglas, fuentes, sumideros y saneadores (todo en tablas)
  proyecto.py     carga de archivos, imports, clases, herencia
  motor.py        el análisis de flujo de datos interprocedural
  reglas_ast.py   reglas que solo miran la forma del código
  config.py       taintlens.toml
  supresion.py    comentarios de ignorar y baseline
  informes.py     texto, JSON, SARIF, HTML, Markdown
  generador.py    programas con respuesta conocida (banco de pruebas)
  corpus.py       casos escritos a mano y limitaciones conocidas
  bench.py        comparación con patrones y Bandit
  cli.py          línea de comandos
tests/            409 tests
examples/         app vulnerable, app corregida, CI, configuración
docs/             TUTORIAL.md, DISENO.md, BENCH.md
```

## Requisitos y licencia

Python 3.11 o superior. Sin dependencias en tiempo de ejecución (solo `pytest` para desarrollar). Bandit es opcional y solo se usa en `taintlens bench`. Licencia MIT.

Hecho por Jaime Sánchez Vicente con ayuda de un asistente de IA para escribir y revisar el código.
