# Matriz de cobertura por idioma y ataque

Esta matriz describe el **manifiesto predeterminado actual**. No afirma que exista cobertura multilingüe completa. Distingue el idioma de los prompts de los patrones del detector que reconocen señales lingüísticas.

## Catálogo predeterminado actual

El manifiesto contiene 14 pruebas:

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
