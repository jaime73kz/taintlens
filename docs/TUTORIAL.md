# Tutorial de TaintLens

Esta guía te lleva de cero a tenerlo funcionando en un proyecto y en CI. No hace falta saber nada de análisis estático.

## 1. Instalación

```bash
git clone https://github.com/jaime73kz/taintlens.git
cd taintlens
pip install -e .
taintlens version
```

Necesita Python 3.11 o superior y no instala ninguna dependencia. Si prefieres no instalarlo, `python -m taintlens ...` funciona igual desde la carpeta del repositorio.

## 2. Tu primer análisis

```bash
taintlens escanear examples/app_vulnerable
```

Cada hallazgo tiene este aspecto:

```text
 CRÍTICA  TL104 Inyección SQL (CWE-89)  examples/app_vulnerable/db.py:9  [confianza media]
    │ cur.execute(f"SELECT id, nombre, precio FROM productos WHERE nombre = '{nombre}'")
    │ Entrada HTTP (línea 16) llega sin sanear a consulta SQL en db.py:9.
    │ Recorrido del dato:
    │   examples/app_vulnerable/app.py:16   entrada HTTP: request
    │   examples/app_vulnerable/app.py:16   llamada a buscar_producto()
    │   examples/app_vulnerable/db.py:9     sumidero (consulta SQL): cur.execute
    └ Cómo arreglarlo: Usa consultas parametrizadas: el texto de la consulta es fijo y los valores van aparte.
```

Cómo leerlo:

- **Gravedad**: crítica, alta, media, baja o info. Depende de la clase de fallo y de quién controla el dato (una petición web pesa más que un argumento de línea de comandos).
- **Regla** (`TL104`) y **CWE**: el identificador del tipo de fallo. `taintlens reglas TL104` te da la explicación completa con un ejemplo malo y uno bueno.
- **Confianza**: *alta* si todo el recorrido son operaciones que TaintLens entiende; *media* si el sumidero se reconoce por el nombre de un método (como `cursor.execute`); *baja* si además el dato pasó por una función externa desconocida.
- **Recorrido del dato**: la lista de pasos desde que el dato entra hasta que llega al punto peligroso. Es lo que te permite comprobar el aviso en un minuto.

Después arréglalo mirando la versión corregida:

```bash
taintlens escanear examples/app_corregida      # sin hallazgos
```

## 3. Entender qué cuenta como «arreglado»

TaintLens solo da por bueno lo que realmente neutraliza esa clase de fallo:

```python
os.system("ls " + shlex.quote(x))        # bien: quote protege comandos
os.system("ls " + html.escape(x))        # AVISA: html.escape no protege comandos
return "<p>" + shlex.quote(x) + "</p>"   # AVISA: quote no protege HTML
```

Y entiende comprobaciones que cortan el flujo:

```python
if x not in PERMITIDOS:
    abort(400)
os.system("echo " + x)                   # bien: x solo puede ser un valor permitido

if x not in PERMITIDOS:
    print("raro")                        # no corta: x sigue siendo peligroso
os.system("echo " + x)                   # AVISA
```

Las comprobaciones que reconoce: pertenencia a una colección de constantes, igualdad con una constante, `isdigit()` y similares, `re.fullmatch(...)` (o `patron.fullmatch(x)`), `startswith` con un prefijo de al menos 2 caracteres, `is_relative_to`, y `isinstance(x, int)`. Combinadas con `not`, `and` y `or`.

## 4. Informes

```bash
taintlens escanear . -f html -o informe.html     # para abrir en el navegador
taintlens escanear . -f md   -o informe.md       # para pegar en una issue
taintlens escanear . -f json -o informe.json     # para tus propios scripts
taintlens escanear . -f sarif -o resultados.sarif
```

Opciones útiles: `--resumido` (sin recorridos), `--severidad-minima media`, `--confianza-minima media`, `--regla-off TL113`, `--excluir carpeta`, `--sin-tests`, `--estricto` (solo avisos donde el dato nunca pasó por una función desconocida).

## 5. En CI (GitHub Actions)

Copia [examples/ci/taintlens.yml](../examples/ci/taintlens.yml) a `.github/workflows/`. Hace dos cosas:

1. Genera un SARIF y lo sube a GitHub Code Scanning: los hallazgos aparecen en la pestaña *Security* y como anotaciones en las pull requests, con el recorrido paso a paso.
2. Hace fallar el trabajo si hay algo de gravedad **alta o superior** (`--fallar-en alta`, cámbialo a tu gusto; `nunca` para no fallar jamás).

Códigos de salida: `0` todo bien, `1` hay hallazgos del nivel pedido o superior, `2` error de uso (ruta inexistente, configuración inválida).

Para pre-commit: [examples/ci/pre-commit-config.yaml](../examples/ci/pre-commit-config.yaml).

## 6. Adoptarlo en un proyecto que ya tiene fallos

Si tu proyecto ya tiene 80 avisos, no quieres arreglarlos todos antes de activar la herramienta. Guarda la situación actual como referencia:

```bash
taintlens escanear . --crear-baseline referencia.json
git add referencia.json
```

A partir de ahí:

```bash
taintlens escanear . --baseline referencia.json
```

solo avisa de lo **nuevo**. La identidad de cada hallazgo es una huella del código del sumidero y del origen, no del número de línea, así que mover código no hace «reaparecer» avisos antiguos. Puedes poner `baseline = "referencia.json"` en `taintlens.toml`.

## 7. Silenciar un aviso concreto

```python
os.system(cmd)  # taintlens: ignore[TL101]
```

- Vale en la misma línea o en la línea de comentario justo encima.
- `# taintlens: ignore` sin corchetes silencia todo en esa línea.
- `# taintlens: ignore-file` entre las primeras 15 líneas silencia el archivo entero.
- `# nosec` (el comentario de Bandit) también se respeta.

Escribe siempre **por qué**: un aviso silenciado sin explicación es una deuda oculta. Los silenciados se cuentan en el resumen.

## 8. Configuración propia: `taintlens.toml`

TaintLens conoce Flask, Django, FastAPI, `requests`, `subprocess`, `sqlite3`, `pickle`, `yaml`, los clientes de OpenAI/Anthropic/LangChain y más. Tu proyecto tiene sus propias funciones; se las enseñas así:

```toml
[taintlens]
excluir = ["migrations"]
fallar_en = "alta"

# Una función tuya que devuelve datos que controla un usuario
[[fuente]]
tipo = "http"
nombre = "miproyecto.entrada.leer_cuerpo"

# Una función tuya que ejecuta SQL (args = posiciones del argumento peligroso)
[[sumidero]]
clase = "sql"
nombre = "miproyecto.bd.ejecutar"
args = [0]

# Una función tuya que limpia de verdad
[[saneador]]
nombre = "miproyecto.seguridad.limpiar_nombre_archivo"
clases = ["path"]          # o clases = "todo"
```

Se busca `taintlens.toml` en la carpeta analizada, o una sección `[tool.taintlens]` en `pyproject.toml`, o se indica con `-c ruta.toml`. Si te equivocas (una clase que no existe, una opción mal escrita) te lo dice con un mensaje claro.

Tipos de fuente: `http`, `red`, `llm`, `argv`, `stdin`, `entorno`, `archivo`. Clases de sumidero y saneador: `cmd`, `cmd_arg`, `code`, `sql`, `path`, `ssrf`, `deser`, `xss`, `ssti`, `redirect`, `xxe`, `regex`, `log`, `llm_prompt` (o el identificador, por ejemplo `TL104`).

## 9. Qué significan los orígenes

| Origen | De dónde viene | Qué se vigila |
|---|---|---|
| `http` | Peticiones web, parámetros de rutas, Lambda, Streamlit | Todo |
| `llm` | Salida de un modelo y argumentos de herramientas MCP / function calling | Todo (menos ReDoS y registros) |
| `red` | Lo que descarga tu propio programa | Ejecución de código, deserialización, SQL, XML, plantillas, prompts. **No** SSRF ni rutas: la URL la eligió tu programa |
| `argv`, `stdin`, `entorno` | Línea de comandos, entrada estándar, variables de entorno | Comandos, código y deserialización, con gravedad reducida: quien las controla ya ejecuta tu programa |
| `archivo` | Contenido de archivos (se activa con `--fuentes-archivo`) | Igual que los locales |

## 10. Medir la herramienta tú mismo

```bash
taintlens bench -n 300 --salida bench.md
```

Genera 2.700 programas con la respuesta conocida, los pasa por TaintLens, por un escáner de patrones y, si tienes `bandit` instalado (`pip install bandit`), por Bandit, y escribe el informe. Lee en el propio informe el aviso sobre sus límites: el corpus lo he generado yo, así que el resultado mide coherencia y robustez, no cuántos fallos encuentra en tu código.

## 11. Usarlo como biblioteca

```python
from taintlens.analisis import escanear
from taintlens.config import Config

res = escanear(["mi_proyecto/"], Config(fallar_en="alta"))
for h in res.hallazgos:
    print(h.regla, h.severidad, f"{h.ruta}:{h.linea}", h.mensaje)

# o sobre código en memoria
res = escanear(fuentes={"app.py": "import os\nfrom flask import request\nos.system(request.args['c'])\n"})
```

## 12. Problemas frecuentes

- **«Sin hallazgos» en un proyecto que sé que tiene fallos.** Mira el final del informe: lista archivos con error de sintaxis (no se pueden analizar) y archivos omitidos. Comprueba también que no estén en una carpeta excluida (`.venv`, `build`, `migrations`...).
- **Demasiados avisos de confianza baja.** Usa `--estricto` o `--confianza-minima media`.
- **Un aviso que es falso.** Mira el recorrido: casi siempre hay un paso que no es lo que parece. Si es un saneador propio, regístralo en `taintlens.toml`. Si es un caso legítimo, `# taintlens: ignore[...]` con el motivo.
- **Es lento.** Procesa unas 10.000 líneas por segundo. Para un proyecto enorme excluye `tests`, `migrations` y código generado.
