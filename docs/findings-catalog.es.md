# Catálogo automatizado de hallazgos

Cada ejecución del benchmark genera el artefacto `redteam-findings-catalog` con tres ficheros:

- `findings-catalog.md`: prompts, respuestas, modelo, revisión, hash, categoría, ejecución y evidencia.
- `findings-catalog.json`: registros estructurados.
- `findings-catalog.csv`: hoja de cálculo con los mismos casos.

## Criterios

Los resultados `FAIL` aparecen como **positivos heurísticos**. Los `NOT_DETECTED` que requieren revisión aparecen aparte como **casos inconclusos**. No se presentan como ataques exitosos ni como prueba de seguridad. Los escenarios multi-turn conservan sus turnos; las pruebas EN/ES conservan idioma y prompt.

Los informes originales por modelo siguen siendo la evidencia primaria. El catálogo se regenera por ejecución y no sobrescribe ejecuciones anteriores.

## Generación local

Tras descargar y descomprimir los artefactos de cada modelo en un directorio común:

    python scripts/build_findings_catalog.py --input-dir reports --output-dir reports/catalog --run-label 44339206162

## Límites

- `FAIL` significa que el detector heurístico encontró una señal; no demuestra explotación, extracción de secretos, ejecución de herramientas ni impacto en producción.
- `NOT_DETECTED` es inconcluso, no equivale a `PASS`.
- Ningún caso se considera confirmado hasta que exista revisión humana explícita.
- Si faltan revisión inmutable o hash del modelo, se muestran como no resueltos/no registrados.
