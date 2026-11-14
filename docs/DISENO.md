# Diseño de TaintLens

Este documento explica cómo está hecho TaintLens, por qué se tomaron esas decisiones y dónde falla. Está pensado para leerlo antes de hablar del proyecto con alguien.

## 1. El problema

Una vulnerabilidad de inyección tiene siempre la misma forma: un dato que controla un atacante (**fuente**) llega, sin neutralizar, a una operación peligrosa (**sumidero**). Entre ambos puede haber variables, funciones, clases y archivos. Buscar el sumidero con una expresión regular da muchísimas falsas alarmas (casi todo uso de `subprocess` es legítimo) y no ve los saneadores ni los caminos entre archivos. Hay que **seguir el dato**.

## 2. Arquitectura

```
archivos .py ──▶ proyecto ──▶ motor ──▶ hallazgos ──▶ filtros ──▶ informes
                 (ast,        (flujo de    + reglas    (config,     (texto, JSON,
                 imports,      datos)       de forma    ignore,      SARIF, HTML,
                 clases)                                baseline)    MD)
```

Todo se apoya en el módulo `ast` de la biblioteca estándar. No ejecuta ni importa el código analizado (hay un test que lo comprueba).

### 2.1 Modelo de datos (`modelo.py`)

Un dato contaminado es un `Taint`: `tipo` (de dónde viene), `origen` (línea del código), `pasos` (por dónde ha viajado, para mostrarlo), `limpio` (clases de fallo ya neutralizadas) e `incierto` (pasó por una función externa desconocida). Un conjunto de taints (`Taints`) conserva, para cada combinación distinta, el recorrido más corto. Todo es inmutable, así que unir ramas del flujo es barato y seguro.

**Decisión clave: el saneamiento es por clase.** `shlex.quote` marca `{cmd, cmd_arg}` como limpio, no «todo». Así `html.escape` antes de `os.system` no engaña al analizador. Es la diferencia más visible con un buscador de patrones, y se mide en el banco de pruebas (variante `saneador_equivocado`).

### 2.2 Índice del proyecto (`proyecto.py`)

Carga archivos, calcula nombres de módulo, resuelve `import`, `from x import y` y los imports relativos, indexa funciones (incluidas las anidadas y los métodos) y clases con su herencia (orden de resolución con protección frente a ciclos). Un archivo con error de sintaxis, binario o enorme se registra y se salta: nunca tumba el análisis.

### 2.3 Motor (`motor.py`)

**Análisis por resúmenes.** Cada función se analiza una vez con sus parámetros como símbolos (`param:0`, `param:1`...). El resultado es un *resumen*:

- `retorno`: qué taints devuelve (puede incluir símbolos: «devuelve el parámetro 0 saneado con shlex»).
- `sumideros`: a qué sumideros llegan sus parámetros, con el recorrido dentro de la función.
- `campos`: qué campos de objeto escribe a partir de sus parámetros.

Al encontrar una llamada, se **aplica** el resumen: se sustituye cada símbolo por los taints reales de los argumentos. Una función se analiza una sola vez aunque la llamen cien veces, y se compone sin límite de profundidad.

**Punto fijo.** Los resúmenes dependen unos de otros (y de los campos de objeto), así que se recalculan por rondas hasta que ninguno cambia (máximo 6 rondas; la recursión y la recursión mutua convergen porque el dominio es finito: las claves de taint son tipo + origen + clases limpias + incertidumbre). Una pasada final con los resúmenes estables genera los hallazgos.

**Sensible al flujo.** Las sentencias se ejecutan en orden sobre un entorno. `v = request.args['x']; v = 'fijo'` deja `v` limpio. Las ramas `if/else`, `try/except`, `match` se unen al final. Los bucles se ejecutan una vez y una segunda solo si el entorno cambió (así los bucles anidados no explotan). Las guardas (`if x not in OK: return`) limpian la variable en la rama donde se cumplen, y si una rama termina (`return`, `raise`, `abort()`, `sys.exit()`) el flujo posterior solo hereda la otra.

**Campos de objeto.** `self.x = valor` escribe en un mapa global `(clase, atributo)`, que otros métodos leen. El tipo de una variable se infiere de `x = Clase(...)`, de anotaciones de parámetros, de `self` y de campos tipados. Los constructores se tratan como llamadas a `__init__` (o, en dataclasses, como escrituras en campos por posición).

**Puntos de entrada.** Una función es un punto de entrada si tiene un decorador de ruta web (`@app.route`, `@app.get`...), de herramienta de agente (`@mcp.tool()`, `@tool`, `@function_tool`...), de CLI (`@click.command`), si es un `lambda_handler`, o una vista de Django. En esos casos se analiza una segunda vez con los parámetros contaminados con el origen correspondiente (las herramientas de un agente: `llm`). Además, en rutas de Flask, devolver texto contaminado es un sumidero de XSS.

**Ejecución en línea.** Las lambdas y las funciones anidadas se ejecutan en el sitio donde se llaman, con el entorno del llamador, para ver las variables capturadas. `Thread(target=f, args=...)`, `executor.submit(f, x)` y similares se tratan como la llamada `f(x)`.

**Diccionarios literales** con claves de texto constante se siguen clave a clave (`d = {"a": tainted, "b": "ls"}; os.system(d["b"])` no avisa).

### 2.4 Catálogo (`catalogo.py`)

Todo el conocimiento del mundo está en tablas: 24 reglas con su CWE/OWASP/ejemplo, 14 fuentes, 30 entradas de sumideros y los saneadores. Los sumideros se reconocen por nombre cualificado (`os.system`, resolviendo alias de imports) o, con menos confianza, por la cola del nombre de un método (`cursor.execute`, `client.chat.completions.create`), y a veces condicionados al nombre del receptor. Añadir una API es añadir una fila (o unas líneas de TOML).

Casos con lógica propia: `subprocess` (con `shell=True` el dato es el comando; con lista, el primer elemento es el programa y el resto son argumentos; `["sh", "-c", x]` cuenta como comando), `yaml.load`/`torch.load`/`numpy.load` según sus argumentos, y SSRF/redirección cuando el dato solo cambia la ruta tras un prefijo `https://host/`.

### 2.5 Reglas de forma (`reglas_ast.py`)

Las que no necesitan seguir datos (secretos, TLS desactivado, `debug=True`...). Los secretos usan una heurística que intenta no avisar de `token_type = "quoted-string"`: exige mezcla de letras y dígitos o mucha entropía, descarta nombres como `*_type` o `*_url`, y valores que parecen identificadores o marcadores de plantilla. Se eliminan duplicados cuando una regla de flujo ya cubre la misma línea.

### 2.6 Salidas (`informes.py`)

SARIF 2.1.0 con reglas completas (CWE, etiqueta OWASP, `security-severity`, texto de ayuda con ejemplo) y `codeFlows` con el recorrido, que GitHub Code Scanning muestra paso a paso. La huella (`partialFingerprints`) se calcula sobre el texto del sumidero y del origen, no sobre la línea, para que el baseline y el seguimiento de alertas sobrevivan a mover código. El HTML es un único archivo sin recursos externos y con todo escapado.

## 3. Decisiones de precisión (y por qué)

- **Los datos locales (`argv`, `stdin`, entorno) bajan dos niveles de gravedad** y solo vigilan comandos, código y deserialización. Quien controla tu línea de comandos ya ejecuta tu programa. Esta decisión salió de analizar la biblioteca estándar: sin ella, cientos de avisos eran ruido.
- **Los datos de red solo importan si acaban ejecutándose o interpretándose.** Una URL que sale de una respuesta que tu programa pidió no es un SSRF controlado por un atacante.
- **El método con el mismo nombre en otra clase no cuenta.** Las llamadas a un método sin tipo conocido solo se resuelven por nombre si hay un único candidato en el mismo módulo o en los que importa (comprobado contra un entorno de 8.000 archivos, donde el emparejamiento global creaba rutas absurdas).
- **Las funciones desconocidas propagan el dato pero con confianza baja.** Lo contrario (asumir que limpian) escondería fallos; lo contrario del contrario (confianza alta) llenaría de ruido. `--estricto` las oculta.
- **Un aviso siempre trae su recorrido.** Una herramienta de seguridad que dice «hay un fallo aquí» sin demostrarlo cuesta más tiempo del que ahorra.

## 4. Cómo se mide (`bench`, `generador`, `corpus`)

Tres niveles, de menos a más independiente de mí:

1. **Programas generados** (`generador.py`): 9 clases, cadenas de 0 a 4 transformaciones elegidas entre 18 (alias, diccionarios, listas, tuplas, funciones auxiliares, clases, ramas, bucles, `try`, comprensiones, `:=`...), sumidero directo o dentro de una función auxiliar, y 16 variantes de programa seguro y 13 de vulnerable (saneador equivocado, señuelo, guarda que no corta, recontaminación, saneado solo en una rama, prefijos débiles...). La etiqueta sale de cómo se montó el programa. **Lo escribí yo**, igual que el motor: mide coherencia, no generalización.
2. **Corpus a mano** (`corpus.py`): 56 casos en estilos de código reales y casos seguros difíciles, más 4 limitaciones que se mantienen fallando a propósito (un test falla si alguna empieza a pasar, para obligar a actualizar este documento).
3. **Código ajeno**: la biblioteca estándar y un entorno de 3,6 millones de líneas. No hay etiquetas, así que mide robustez y velocidad, y sirve para encontrar falsas alarmas revisándolas a mano. Así se descubrieron varios errores de diseño (sección 3).

Comparaciones: un escáner de patrones con **el mismo catálogo y sin flujo** (qué aporta el seguimiento del dato) y **Bandit 1.9.4** real (solo en las clases donde tiene reglas, y señalando las que no tiene).

## 5. Límites conocidos

Son reales; algunos están cubiertos por los tests (`corpus.py`, `limitacion=True`).

| Límite | Efecto | Por qué |
|---|---|---|
| Despacho dinámico (`getattr(obj, nombre)(...)`) | No se sigue (falso negativo) | No se sabe qué función se llamará sin ejecutar |
| Funciones guardadas en objetos (`partial(f, x)()`, callbacks en diccionarios) | No se sigue | No hay análisis de punteros |
| Datos que viajan por una base de datos o archivo y vuelven (XSS almacenado) | No se sigue | El motor no modela el almacenamiento externo |
| Campos de objeto por clase, no por instancia | Falsa alarma si una instancia está contaminada y otra no | Más precisión exigiría análisis de alias |
| Contenedores sin clave constante (listas, diccionarios dinámicos) | Un elemento contaminado contamina el contenedor entero | Simplificación deliberada |
| Bibliotecas no catalogadas | El dato «pasa» con confianza baja; los saneadores propios no se conocen | Se resuelve con `taintlens.toml` |
| Solo Python | — | — |
| `exec`/`eval` dentro de cadenas de código, metaprogramación, decoradores que cambian la firma | No se sigue | Fuera del alcance de un análisis estático razonable |
| Condiciones que no entiende (p. ej. un `if` sobre una función propia que valida) | Falsa alarma | Solo reconoce las guardas de la lista del tutorial |
| El límite de 6 rondas de punto fijo y 4 niveles de ejecución en línea | En cadenas absurdamente largas podría perderse un recorrido | Garantiza que el tiempo no explote |

Y una limitación de método: el análisis estático puede fallar en los dos sentidos. Ninguna cifra de este repositorio dice «encuentra todo lo que hay»; dicen cómo se comporta con casos conocidos.

## 6. Lo que haría con más tiempo

- Un analizador de alias para separar instancias de la misma clase.
- Modelado de ORMs (Django, SQLAlchemy) para seguir datos por la base de datos.
- Modo incremental para analizar solo los archivos cambiados y sus dependientes.
- Un corpus externo: vulnerabilidades reales corregidas en proyectos de código abierto (versión anterior = positivo, versión corregida = negativo), que es la única forma de que la medida no dependa de lo que yo imagine.
- Arreglos automáticos sugeridos para las clases más claras (consultas parametrizadas, `subprocess` con lista).

## 7. Sobre cómo se hizo

El diseño, la implementación y las pruebas se hicieron con la ayuda de un asistente de IA, que escribió y revisó el código bajo mi dirección, y se contrastaron con ejecuciones reales (la biblioteca estándar, Bandit). Las partes que son decisiones de diseño (por clase, resúmenes, punto fijo, límites) las puedo explicar y defender; este documento existe para eso.
