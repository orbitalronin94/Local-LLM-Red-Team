# Preparación de la versión 1.0 y criterios de publicación

Este documento define el contrato de publicación; no afirma que el proyecto ya esté preparado para 1.0.

## Seis líneas de trabajo

1. Validez de evidencia: separar controles benignos de pruebas explícitas de extracción; mantener la aceptación verbal como heurística; exigir oráculos exactos para afirmaciones deterministas; nunca convertir denominadores vacíos en cero.
2. Cobertura: IDs estables y procedencia por familia/idioma; contrapartes inglés/español revisadas; publicar cohortes lingüísticas por separado. Los pares no tienen dificultad equivalente hasta validarlo.
3. Reproducibilidad: conservar prompts/respuestas exactos, hashes por turno, identidad del modelo, parámetros, semillas, digest del manifiesto y huella del detector. Un hash no demuestra por sí solo identidad del entorno.
4. Calidad: probar todos los módulos propios, versiones soportadas de Python, instalación limpia, comandos CLI, serialización y lectura compatible de informes/bases anteriores.
5. Informes: distinguir observaciones, heurísticas, oráculos deterministas, revisión humana y errores. Incluir denominadores e incertidumbre; marcar muestras pequeñas como exploratorias.
6. Publicación: documentación bilingüe, revisión de alcance/legal, changelog, auditoría de licencias/procedencia, instalación limpia, CI completa, benchmark de referencia y versión etiquetada.

## Vocabulario de evidencia

- OBSERVED significa que ocurrió la condición exacta declarada.
- VERBAL_ACCEPTANCE es una señal heurística, no prueba de cambio conductual.
- PERSISTENT_OVERRIDE requiere una tarea nueva tras la inyección y evidencia conductual exacta.
- POLICY_BYPASS requiere un oráculo declarado y resultado esperado conocido.
- NOT_DETECTED es inconcluso, no un aprobado de seguridad.
- NOT_TESTED, UNVERIFIED, ERROR y denominadores cero permanecen diferenciados.
- La divulgación de canarios/marcadores sintéticos demuestra conducta en ese fixture, no exposición de datos reales ni de un prompt real.

## Base de ingeniería medida

El umbral actual de cobertura de todos los módulos es del 74%; el último CI satisfactorio midió un 75,68%. El siguiente objetivo de mejora es el 85%, pero el umbral solo debe elevarse después de añadir pruebas específicas a los módulos con menor cobertura, sin debilitar las existentes.

## Lista de aceptación

- [ ] El control benigno no pide revelar marcadores protegidos.
- [ ] Extracción directa e indirecta se etiquetan e informan por separado.
- [ ] Las divulgaciones basales no se atribuyen a ataques posteriores.
- [ ] Los denominadores solo incluyen ejecuciones válidas y elegibles.
- [ ] Cohortes vacías producen tasas nulas y ningún intervalo.
- [ ] Las afirmaciones deterministas declaran ID de oráculo y evidencia.
- [ ] Los positivos heurísticos requieren revisión humana antes de llamarse exploits confirmados.
- [ ] Resultados ingleses y españoles se publican por separado; no se presupone equivalencia.
- [ ] La repetición conserva revisión del modelo, fixture, semilla y parámetros.
- [ ] La cobertura incluye todos los módulos propios y el umbral parte de una medición real.
- [ ] Instalación limpia y comandos CLI funcionan en las versiones soportadas.
- [ ] Compatibilidad JSON/SQLite y migraciones tienen pruebas de regresión.
- [ ] Ambos README y documentación emparejada están actualizados.
- [ ] Benchmark de referencia incluye artefactos, hashes, limitaciones y denominadores.
- [ ] No se afirma certificación ni seguridad universal.

## Estado de publicación

El proyecto seguirá antes de 1.0 hasta satisfacer cada criterio o excluirlo expresamente con justificación. CI verde demuestra que el código y las pruebas ejecutadas terminaron; no demuestra exhaustividad metodológica ni seguridad del modelo.