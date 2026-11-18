# Hoja de ruta de investigación: ampliar la superficie de red teaming

Esta hoja convierte investigación reciente en extensiones comprobables y asumibles con pocos recursos para Local LLM Red Team. Es una lista de trabajo: no afirma que estas capacidades estén implementadas.

## Principios de diseño
- Mantener el núcleo local-first y utilizable con CPU.
- Cada prueba tendrá ID y versión estables, atribución a un paper o hipótesis explícita y posibilidad de repetición.
- Separar el comportamiento textual del modelo de los efectos observables sobre herramientas o estado.
- Emparejar ataques con controles benignos; medir utilidad y falsos positivos además del resultado adversarial.
- Los detectores heurísticos no son verdad de referencia. Hay que conservar las respuestas originales.
- La ejecución real de herramientas solo se habilitará mediante un sandbox explícito. El texto simulado seguirá identificado como simulación.

## Prioridad 1 — Ataques adaptativos y de varios turnos
**Base científica:** [MAZE: One Refusal Isn’t Enough (EMNLP 2026)](https://aclanthology.org/2026.emnlp-main.2577/), [Adaptive Adversaries (arXiv:2607.18063)](https://arxiv.org/abs/2607.18063) y [AgentLAB (arXiv:2602.16901)](https://arxiv.org/abs/2602.16901).

Pasar de prompts aislados a conversaciones con escenarios: construcción gradual de contexto y legitimidad; reformulación después de una negativa; desviación progresiva del objetivo; inyección de tareas y encadenamiento de herramientas; envenenamiento de memoria persistente y activación posterior.

Usar ficheros de escenario con IDs estables, turnos ordenados, límite de seguridad probado, condiciones de parada y presupuesto máximo de turnos. Guardar la transcripción completa e identificar el primer turno que cruza el límite. Comparar el caso de un solo turno con la misma petición final después de construir contexto.

## Prioridad 2 — Fronteras de herramientas, recuperación y MCP
**Base científica:** [MCP Security Bench, ICLR 2026](https://openreview.net/pdf?id=irxxkFMrry), [SafeClawBench (arXiv:2606.18356)](https://arxiv.org/abs/2606.18356) y [Toward Secure LLM Agents (arXiv:2606.10749)](https://arxiv.org/abs/2606.10749).

Ir más allá del texto citado simulado mediante un harness opcional de herramientas locales: descripciones hostiles y colisiones de nombres; resultados maliciosos y escalada mediante errores falsos; argumentos fuera de alcance o que elevan privilegios; transferencia de herramientas y confusión de autoridad; envenenamiento de recuperación y pérdida de procedencia.

Todas las herramientas deben ser deterministas y estar aisladas. Empezar con herramientas ficticias que solo lean/escriban en un directorio temporal o estado en memoria. Nada de correo, shell, navegador, red, nube o credenciales de producción. Registrar por separado las llamadas propuestas y las realmente ejecutadas.

## Prioridad 3 — Separar aceptación semántica de impacto real
**Base científica:** [SafeClawBench](https://arxiv.org/abs/2606.18356) distingue aceptación semántica, evidencia de auditoría y daño observado en herramientas/estado dentro de un sandbox.

Añadir resultados separados: aceptación semántica; límite de política cruzado; llamada a herramienta intentada; efecto observado en sandbox; evidencia de auditoría. Así no confundimos decir que se hará algo con ejecutar realmente una acción. Mantener separados ASR, utilidad benigna, utilidad bajo ataque, latencia y errores de ejecución.

## Prioridad 4 — Suite multilingüe con español y cambio de idioma
**Base científica:** [MMJail (WOAH 2026)](https://aclanthology.org/2026.woah-1.36/), [Does Safety Reasoning Travel? (ORACLE 2026)](https://aclanthology.org/2026.oracle-main.13/), [IndicSafeEval (Findings EMNLP 2026)](https://aclanthology.org/2026.findings-emnlp.2457/) y [Mātṛkā (2025)](https://aclanthology.org/2025.bhasha-1.10/).

Construir familias emparejadas en inglés y castellano: formulaciones naturales en español y variantes regionales; transferencia entre idiomas; cambio de idioma dentro de un prompt y entre turnos; tildes, puntuación, confusables Unicode y transliteración; persuasión y escalada gradual en varios turnos.

Mantener emparejadas intención y dificultad, añadir controles benignos difíciles e informar resultados por idioma. Los defectos de traducción pueden falsear conclusiones: conservar original, traducción revisada y proceso de revisión.

## Prioridad 5 — Ataques lógicos, estructurales y composicionales
**Base científica:** [Logic Jailbreak (Findings ACL 2026)](https://aclanthology.org/2026.findings-acl.25/), [JailbreakRadar (ACL 2025)](https://aclanthology.org/2025.acl-long.1045/) y [LAAF (arXiv:2603.17239)](https://arxiv.org/abs/2603.17239).

Añadir familias controladas para reformulación lógica/formal y premisas contradictorias; delimitadores anidados, estructuras malformadas y confusión de roles; transformaciones de codificación y normalización; combinaciones por capas de técnicas versionadas por separado; payloads condicionados por activadores en distintas fases de conversación.

No generar un corpus combinatorio ilimitado. Usar mutaciones deterministas y acotadas, deduplicación, IDs de semilla y linaje de cada mutación.

## Prioridad 6 — Investigación de atacantes adaptativos ligeros
**Base científica:** [Adversarial Prompt Distillation (Findings AACL 2026)](https://aclanthology.org/2026.findings-aacl.75/) estudia transferir capacidad de generación de ataques desde modelos grandes a modelos pequeños.

Para este proyecto orientado a CPU, empezar con una línea base determinista de mutación y búsqueda (plantillas de paráfrasis, variantes estructurales, variantes lingüísticas y selección condicionada por respuestas). Después comparar con un atacante local pequeño. Medir coste de generación, consultas, tiempo, diversidad y nuevos hallazgos, no solo ASR. Mantener atacante y objetivo separados cuando sea posible; etiquetar claramente los resultados de self-play.

## Protocolo de evaluación obligatorio
- IDs y versiones estables, cita de origen y breve modelo de amenaza.
- Controles benignos emparejados y línea base de un turno cuando proceda.
- Al menos dos ejecuciones con semillas independientes para casos estocásticos/adaptativos; más cuando los resultados sean infrecuentes.
- Conservar transcripciones, revisión del modelo, cuantización, parámetros de inferencia, hash del manifiesto y metadatos del entorno.
- Informar recuentos e incertidumbre, no solo porcentajes; evitar rankings con muestras pequeñas o desequilibradas.
- Revisión humana de resultados semánticos ambiguos. Un modelo juez puede ayudar, pero nunca convertirse silenciosamente en la verdad de referencia.
- Tests de regresión para generación determinista, serialización, replay y detector.

## Orden de implementación propuesto
1. Esquema de escenarios y tests de transcripción/replay multi-turno.
2. Pares emparejados inglés/español y controles benignos.
3. Esquema de resultados estructurados y evidencia de auditoría.
4. Motor determinista de mutaciones con límites y deduplicación.
5. Sandbox opcional de herramientas simuladas e interfaz compatible con MCP.
6. Comparativa de atacantes adaptativos e informes de benchmark.

## Referencias y límites
Estos trabajos motivan técnicas candidatas; no demuestran que todos los ataques publicados se transfieran a modelos locales pequeños y cuantizados. Hay que reproducir solo lo que encaje con nuestro modelo de amenaza, fijar versiones de papers/código/datasets y medir los modelos reales del repositorio. Algunos trabajos son muy recientes y sus datos/código pueden cambiar. Revisar licencias y condiciones de uso antes de importar prompts o corpus.
