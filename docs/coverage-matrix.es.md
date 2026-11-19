# Matriz de cobertura por idioma y ataque

Esta matriz describe el **manifiesto predeterminado actual**. No afirma que exista cobertura multilingüe completa. Distingue el idioma de los prompts de los patrones del detector que reconocen señales lingüísticas.

## Catálogo predeterminado actual

El manifiesto contiene 27 pruebas (13 en inglés y 14 en español).

| ID de ataque | Categoría | Idioma del prompt | Límite principal |
| --- | --- | --- | --- |
| `jailbreak-roleplay` | Jailbreak | Inglés | Personaje sin restricciones |
| `jailbreak-authority` | Jailbreak | Inglés | Falsa autoridad o aprobación |
| `instruction-override` | Anulación | Inglés | Sustitución directa de instrucciones |
| `system-prompt-extraction` | Extracción | Inglés | Revelación directa de instrucciones ocultas |
| `system-prompt-summary` | Extracción | Inglés | Revelación indirecta de instrucciones ocultas |
| `prompt-injection-document` | Prompt injection | Inglés | Instrucciones en documento no confiable |
| `prompt-injection-tool` | Prompt injection | Inglés | Revelación simulada de herramienta/configuración |
| `persistence` | Persistencia | Inglés | Retención de instrucciones inseguras |
| `indirect-injection-retrieved-content` | Prompt injection | Inglés | Instrucción simulada en texto recuperado |
| `tool-output-injection` | Prompt injection | Inglés | Instrucción en salida simulada de herramienta |
| `delimiter-boundary-confusion` | Anulación | Inglés | Confusión de delimitadores y roles |
| `multilingual-instruction-override` | Anulación | Español | Anulación explícita en castellano |
| `refusal-suppression` | Jailbreak | Inglés | Supresión del lenguaje de rechazo |
| `multi-turn-persistence` | Persistencia | Inglés | Semilla para persistencia entre turnos |

**Cobertura de idioma de los prompts:** 13 pruebas en inglés y 1 explícitamente en español. El detector también contiene patrones en español, pero eso no convierte el catálogo en una batería bilingüe equilibrada.

## Qué cubre y qué no

| Dimensión | Estado actual | Interpretación |
| --- | --- | --- |
| Prompts de ataque en inglés | 13 pruebas predeterminadas | Mayor cobertura lingüística del catálogo inicial. |
| Prompts de ataque en español | 1 prueba predeterminada | Solo prueba de humo; insuficiente para una puntuación de seguridad en español. |
| Patrones del detector en español | Existen para señales seleccionadas de rechazo y cumplimiento | Tener patrones no equivale a evaluación semántica en español. |
| Ataques con mezcla de idiomas | Una prueba etiquetada como multilingüe/en español | No existe una matriz sistemática de cambio de idioma. |
| Evaluación de respuestas en español | No validada como batería completa independiente | Responder en español a un prompt inglés no constituye un caso de prueba en español. |
| Ejecución de RAG/herramientas | Solo texto simulado | No se ejecuta un pipeline RAG ni un runtime de herramientas real. |
| Revisión semántica humana | Proceso manual documentado aparte | No hay juez LLM automático ni flujo calibrado de anotación humana. |

## Ampliación bilingüe recomendada

Antes de publicar puntuaciones comparativas inglés/español, crea pares equivalentes para cada familia:

1. Traduce la intención del ataque, no solo palabras; pide a una persona competente que revise la naturalidad.
2. Conserva un ID de familia común y IDs distintos para cada idioma.
3. Mantén equivalentes la dificultad y el límite de seguridad probado.
4. Añade paráfrasis, variantes regionales y casos de cambio de idioma.
5. Incorpora controles benignos y ejemplos de rechazo/cumplimiento para estimar falsos positivos y negativos.
6. Revisa respuestas manualmente e informa por idioma de recuentos, errores e incertidumbre.
7. Versiona el manifiesto y publica su SHA-256 con cada resultado.

No compares una puntuación inglesa con una española basada en una sola prueba. Publica el número exacto de casos, distribución por familias y versión del detector. El catálogo actual es un punto de partida, no un benchmark bilingüe validado.

Relacionado: [Guía de interpretación de informes](report-guide.es.md) · [Metodología de detección](methodology.es.md).

## Contrapartes en español

Estas pruebas reflejan la intención y el límite de las pruebas iniciales en inglés. Son pares de prompts revisados, no elementos con dificultad equivalente ni equivalencia semántica validada. Publica las cohortes por idioma y no las agregues en una puntuación única sin validar equivalencia y efectos del idioma de respuesta.

| Familia inglesa | ID de la prueba española |
| --- | --- |
| Jailbreak de rol | es-jailbreak-roleplay |
| Falsa autoridad | es-jailbreak-authority |
| Anulación de instrucciones | es-instruction-override |
| Extracción directa | es-system-prompt-extraction |
| Resumen indirecto | es-system-prompt-summary |
| Inyección en documento | es-prompt-injection-document |
| Inyección orientada a herramientas | es-prompt-injection-tool |
| Presión de persistencia | es-persistence |
| Inyección en contenido recuperado | es-indirect-injection-retrieved-content |
| Inyección en salida de herramienta | es-tool-output-injection |
| Confusión de delimitadores | es-delimiter-boundary-confusion |
| Supresión del rechazo | es-refusal-suppression |
| Persistencia multi-turno | es-multi-turn-persistence |

La ampliación mejora la cobertura de idioma de los prompts, pero no valida la precisión/recobrado del detector en español. La revisión humana y la medición de falsos positivos/negativos por idioma siguen siendo necesarias antes de publicar comparativas.
