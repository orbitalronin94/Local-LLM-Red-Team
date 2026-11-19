# Perfiles de rendimiento y presupuestos de generación

## Objetivo

Reducir el tiempo de las iteraciones de desarrollo sin alterar el significado ni el alcance del benchmark oficial. El perfil rápido sirve como cribado; no sustituye a la evaluación completa.

## Perfiles

| Perfil | Catálogo estático | Autoataque adaptativo | Escenarios multi-turno fijos | Suite pareada EN/ES | Matriz de semillas/paráfrasis |
| --- | --- | --- | --- | --- | --- |
| quick | Muestra fija de 8 ataques | Omitido | Omitidos | Omitida | Omitida |
| full | Todo el catálogo | Excluido del workflow oficial | Todos los escenarios fijos | Todos los pares y controles | Todas las semillas y variantes configuradas |

La muestra rápida cubre jailbreak, anulación de instrucciones, extracción del sistema, inyección de prompts y persistencia; incluye prompts en inglés y español. Sus IDs exactos viven en QUICK_PROFILE_ATTACK_IDS y el manifiesto seleccionado queda registrado en los metadatos de la ejecución.

En local: local-llm-redteam --profile quick. El perfil rápido es solo estático y no se puede combinar con filtros explícitos --attack o --category. La CLI rechaza esas combinaciones para no cambiar silenciosamente la cohorte solicitada.

El benchmark oficial de siete modelos en GitHub Actions utiliza full y es exclusivamente estático: excluye el autoataque adaptativo para conservar entradas emparejadas y evitar trayectorias de ataque dependientes de las respuestas del objetivo. El perfil completo mantiene escenarios multi-turno fijos, pruebas lingüísticas pareadas, controles benignos y la matriz de robustez. El modo adaptativo sigue disponible en la CLI independiente para investigación exploratoria, pero sus resultados no forman parte de la comparación oficial. Consulta la [metodología del benchmark oficial](official-benchmark-methodology.es.md).

La opción `quick` se selecciona en **Actions → Local model red-team benchmark → Run workflow → `quick`**. Es un perfil de lanzamiento del mismo workflow, no un workflow independiente. Elígelo para un cribado preliminar, una prueba de humo o feedback de desarrollo más rápido cuando baste la cobertura reducida de ocho ataques. Las suites omitidas quedan sin probar y los resultados quick deben mantenerse separados de los de full. Utiliza `full` para la comparación oficial de los siete modelos.

El workflow de GitHub Actions ofrece benchmark_profile al lanzarlo manualmente. El valor predeterminado es full. Los benchmarks activados por push siguen siendo siempre completos, de modo que CI y los artefactos oficiales no pierden cobertura de forma inadvertida.

## Presupuesto de generación

Todos los adaptadores admiten el parámetro opcional --max-output-tokens N. Se traduce a max_tokens en endpoints compatibles con OpenAI y a options.num_predict en Ollama. Si se omite, no se añade ningún límite y se conserva el valor predeterminado del servidor.

Las ejecuciones rápidas del workflow usan un máximo de 192 tokens generados por respuesta. Este límite no se aplica a las ejecuciones completas. Una respuesta puede quedar truncada: se conserva el motivo de finalización y el escáner marca la evidencia truncada por longitud para revisión. Una respuesta truncada no debe interpretarse como rechazo limpio ni como prueba completada. Los informes pareados y de escenarios conservan la procedencia del motivo de finalización y marcan las respuestas truncadas para revisión humana. El protocolo de persistencia aborta una fase de oráculo incompleta y etiqueta la ejecución como `incomplete_truncated_response`; los resúmenes de robustez la cuentan por separado de los errores de transporte y la excluyen de la cohorte válida.

El límite configurado queda registrado en la procedencia del destino y en los metadatos de la ejecución estática. En las demás suites CLI, la procedencia de cada turno registra el límite. Un valor nulo significa que se utilizó el valor predeterminado del servidor. Los informes estáticos también calculan tokens/s de generación por respuesta cuando el adaptador proporciona un recuento de tokens de salida y una latencia positiva. Se publican mediana, p95 y tamaño de muestra; las respuestas sin recuento fiable se omiten. El warmup de una sola respuesta no se considera una medición representativa del rendimiento sostenido.

## Cómo interpretar las comparaciones

- Compara ejecuciones rápidas solo con otras ejecuciones rápidas que compartan perfil, manifiesto, revisión del modelo, build del servidor y límite de generación.
- No mezcles denominadores quick y full ni compares sus tasas como si tuvieran la misma cobertura.
- Un NOT_DETECTED en quick es inconcluso; las suites omitidas quedan SIN PROBAR, no aprobadas.
- Usa full para decisiones de publicación, afirmaciones entre modelos e informes de benchmark publicados.
- Para depurar un detector o una mitigación concreta, usa selecciones locales --attack / --category y registra la selección, porque modifica la cohorte evaluada.

El objetivo es reducir inferencias redundantes por iteración de desarrollo, no debilitar la evidencia de la evaluación oficial.
