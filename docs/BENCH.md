# Banco de pruebas de TaintLens

- Programas generados: **5400** (2700 vulnerables y 2700 seguros), 600 por clase, semilla 1
- TaintLens 1.0.0: 12.781 líneas por segundo (9.32 s en total)

> **Lee esto antes de fiarte de las cifras.** El corpus lo he generado yo con las mismas ideas con las que diseñé el motor. Mide que el motor es coherente y robusto con muchas formas de escribir lo mismo, no que encuentre el 99 % de las vulnerabilidades de cualquier proyecto real. Bandit no sigue datos y solo tiene reglas para algunas clases; la comparación está para ver la diferencia entre mirar patrones y seguir el dato.

## Resultado global (todas las clases)

| Herramienta | Precisión | Cobertura | F1 | VP | FP | FN | VN |
|---|---|---|---|---|---|---|---|
| TaintLens | 100.0 % | 100.0 % | 100.0 % | 2700 | 0 | 0 | 2700 |
| Patrones (sin flujo) |  52.5 % | 100.0 % |  68.9 % | 2700 | 2438 | 0 | 262 |

## Solo las clases donde Bandit tiene reglas (cmd, code, deser, sql, ssrf)

| Herramienta | Precisión | Cobertura | F1 | VP | FP | FN | VN |
|---|---|---|---|---|---|---|---|
| TaintLens | 100.0 % | 100.0 % | 100.0 % | 1500 | 0 | 0 | 1500 |
| Patrones (sin flujo) |  53.1 % | 100.0 % |  69.4 % | 1500 | 1325 | 0 | 175 |
| Bandit 1.9.4 |  54.9 % |  80.7 % |  65.4 % | 1211 | 994 | 289 | 506 |

## Por clase de vulnerabilidad

| Clase | TaintLens (F1) | Precisión | Cobertura | Patrones sin flujo (F1) | Bandit 1.9.4 (F1) |
|---|---|---|---|---|---|
| cmd | 100.0 % | 100.0 % | 100.0 % | 66.7 % | 69.1 % |
| sql | 100.0 % | 100.0 % | 100.0 % | 72.6 % | 72.6 % |
| path | 100.0 % | 100.0 % | 100.0 % | 66.7 % | sin regla |
| code | 100.0 % | 100.0 % | 100.0 % | 70.8 % | 66.1 % |
| deser | 100.0 % | 100.0 % | 100.0 % | 70.6 % | 72.9 % |
| ssrf | 100.0 % | 100.0 % | 100.0 % | 66.7 % | 28.3 % |
| xss | 100.0 % | 100.0 % | 100.0 % | 69.0 % | sin regla |
| ssti | 100.0 % | 100.0 % | 100.0 % | 71.2 % | sin regla |
| redirect | 100.0 % | 100.0 % | 100.0 % | 66.7 % | sin regla |

## Dónde falla TaintLens (por variante)

Ningún fallo en este corpus.

## Detección por tipo de programa vulnerable

| Variante | Programas | Detectados |
|---|---|---|
| directa | 443 | 100.0 % |
| guarda_no_corta | 425 | 100.0 % |
| guarda_otra_variable | 451 | 100.0 % |
| guarda_prefijo_debil | 48 | 100.0 % |
| guarda_ruta_no_corta | 31 | 100.0 % |
| loader_inseguro | 45 | 100.0 % |
| quita_comilla | 55 | 100.0 % |
| recontamina | 120 | 100.0 % |
| reemplazo_ingenuo | 27 | 100.0 % |
| saneador_equivocado | 466 | 100.0 % |
| senuelo | 436 | 100.0 % |
| solo_una_rama | 110 | 100.0 % |
| startswith_barra | 43 | 100.0 % |

## Falsas alarmas por tipo de programa seguro

| Variante | Programas | Falsas alarmas |
|---|---|---|
| ayuda_sanea | 103 | 0 |
| basename | 25 | 0 |
| cast_int | 402 | 0 |
| cast_int2 | 61 | 0 |
| constante | 450 | 0 |
| guarda_host | 39 | 0 |
| guarda_lista | 524 | 0 |
| guarda_prefijo | 53 | 0 |
| html_escape | 40 | 0 |
| isdigit | 389 | 0 |
| markupsafe_escape | 41 | 0 |
| realpath_guarda | 39 | 0 |
| regex_completa | 41 | 0 |
| secure_filename | 38 | 0 |
| shlex_quote | 39 | 0 |
| sumidero_seguro | 416 | 0 |
