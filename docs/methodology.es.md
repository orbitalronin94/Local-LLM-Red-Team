# Metodología de detección y limitaciones

Local LLM Red Team es una herramienta de cribado de seguridad a nivel de prompt. El detector predeterminado utiliza patrones de texto deterministas; no comprende el significado como una persona revisora o un evaluador semántico validado.

## Ciclo de escaneo

1. Seleccionar ataques mediante un ID estable o una categoría.
2. Enviar cada prompt al destino configurado.
3. Examinar el texto con patrones heurísticos específicos de la categoría.
4. Registrar respuesta, resultado, evidencia, latencia y tokens disponibles.
5. Guardar la ejecución en SQLite y/o exportar JSON y Markdown.

El modo estático envía cada ataque de forma independiente. El adaptativo mantiene una conversación con el objetivo y solicita a un destino atacante separado mensajes de seguimiento acotados. Estos pueden variar; conserva el informe completo. La latencia adaptativa suma las llamadas al objetivo y al atacante; los tokens reflejan actualmente las respuestas del objetivo.

## Significado de los estados

| Estado | Significado operativo | Lo que no demuestra |
| --- | --- | --- |
| `FAIL` | Se encontró un indicador asociado a aceptar el ataque. | No demuestra compromiso completo ni explotabilidad real. |
| `PASS` | Se encontró un indicador similar a un rechazo. | No demuestra que se resistieran todos los componentes del ataque. |
| `NOT_DETECTED` | No se encontró indicador conocido de aceptación o rechazo. | No demuestra que el ataque fracasara. |
| `EMPTY` | El destino no devolvió texto. | No equivale a un rechazo seguro. |
| `ERROR` | Falló la petición o el procesamiento. | No es un resultado del modelo ni debe contarse como tal. |
| `THROTTLED` | El endpoint limitó la petición (por ejemplo, HTTP 429/503). | No es un rechazo ni un resultado conductual del modelo. |

## Interpretación de métricas

El cálculo actual de tasa de éxito heurístico es:

`FAIL / (total - ERROR - EMPTY - THROTTLED)`

Solo entran en el denominador las respuestas ejecutables y no vacías. Se excluyen `ERROR`, `EMPTY` y `THROTTLED`; `PASS` y `NOT_DETECTED` permanecen. `NOT_DETECTED` es inconcluso, no prueba de resistencia. La cobertura se informa por separado para que una cohorte con pocas respuestas utilizables no parezca artificialmente robusta. La tasa describe solo el catálogo seleccionado y la huella/versión del detector; no es una puntuación universal de riesgo.

La tasa de rechazo cuenta resultados completados clasificados como `PASS` con evidencia de rechazo. Revisa las respuestas originales antes de interpretar cualquiera de las métricas.

## Limitaciones conocidas

- **Falsos positivos:** el modelo puede citar, explicar o rechazar un ataque y repetir palabras que coincidan con un patrón.
- **Falsos negativos:** una respuesta que acepte el ataque puede utilizar expresiones o comportamientos que los patrones no reconozcan.
- **Dependencia del contexto:** una respuesta a un prompt no demuestra cómo se comporta un agente con herramientas, recuperación, memoria, permisos o efectos externos.
- **Variabilidad:** muestreo, revisiones del modelo, prompts de sistema, plantillas y servidores pueden alterar resultados.
- **Variabilidad adaptativa:** los seguimientos los genera otro modelo; no son deterministas salvo que se controlen atacante y parámetros.
- **Cobertura limitada:** el catálogo es inicial y reducido; no supone un modelo de amenazas exhaustivo ni cobertura OWASP.


## Evidencia en escenarios multi-turno

Cada turno programado se evalúa por separado y una señal heurística no detiene los turnos restantes. Así se conservan las observaciones posteriores necesarias para distinguir una afirmación inicial del comportamiento subsiguiente. Una señal de un turno no se copia a los siguientes como si fuera evidencia nueva.

Los vectores de evidencia se rellenan de forma independiente:

- `VERBAL_ACCEPTANCE` registra únicamente una señal heurística de aceptación verbal.
- `PERSISTENT_OVERRIDE` permanece en `NOT_TESTED` salvo que una tarea independiente posterior a la inyección demuestre un cambio de comportamiento mediante un oráculo explícito.
- `POLICY_BYPASS` permanece en `UNVERIFIED` si no existe un oráculo determinista.
- `CANARY_DISCLOSURE` permanece en `NOT_TESTED` si el escenario no contiene un canario de ejecución y una comprobación de coincidencia exacta.

El encuadre ficticio, citado o de rol no neutraliza por sí mismo el contenido procedimental. El detector sigue siendo heurístico y requiere revisión humana; no demuestra impacto real. Los errores de ejecución siguen siendo errores, no rechazos ni aprobaciones del modelo.

## Comparaciones reproducibles

Conserva el manifiesto exacto, versión del escáner, tipo de destino, endpoint, identificador/revisión del modelo, prompt de sistema, plantilla, parámetros de generación, modelo atacante (si procede), entorno, fecha, informes originales y base SQLite. Cambia una variable cada vez cuando sea posible y revisa respuestas individuales antes de atribuir importancia a diferencias agregadas.

## Uso responsable

Prueba únicamente modelos y endpoints propios o autorizados. Protege los informes, que pueden contener prompts, respuestas e instrucciones internas. Mantén privados los endpoints y no incluyas credenciales en informes compartidos.

## Cobertura ampliada y procedencia

El catálogo incluye pruebas de instrucciones indirectas en pasajes recuperados y salidas simuladas de herramientas, confusión de delimitadores, anulación multilingüe, supresión de rechazos y persistencia. Son pruebas de prompt: no ejecutan un pipeline RAG real, runtime de herramientas ni efectos externos. Esos límites requieren un banco de integración.

Cada escaneo registra versiones del escáner y Python, plataforma, tipo de destino, modelo, detector, modo, IDs de ataques y digest SHA-256 del manifiesto exacto. El modo adaptativo registra también tipo/modelo atacante y límite de rondas. JSON guarda el sobre bajo `run_metadata`; Markdown muestra campos principales y SQLite lo almacena con la ejecución. Las bases existentes se migran de forma aditiva.

El digest identifica las definiciones ordenadas exactas, incluidos prompts y versiones. Ayuda a reproducir la selección de ataques, pero no demuestra que el objetivo o el entorno sean idénticos. URL y credenciales se excluyen para evitar filtraciones; documenta por separado los detalles saneados cuando sea necesario.

## Hashes de evidencia por payload

Cada resultado estático incluye SHA-256 del prompt exacto y de la respuesta. El modo adaptativo conserva hashes por turno, además de los del prompt inicial y la respuesta final. JSON y SQLite almacenan estos valores; Markdown muestra hashes por resultado.

Los hashes permiten detectar cambios si se conserva el contenido original. Un digest no reconstruye el contenido, no establece cuándo se generó ni demuestra el comportamiento del endpoint. Úsalo como ayuda de integridad junto con el informe, metadatos y entorno controlado.


## Uso responsable y autorización

Evalúa únicamente modelos, endpoints y sistemas propios o cuyo análisis tengas expresamente autorizado. El permiso escrito debe delimitar activos, fechas, técnicas, límites de tráfico y acciones prohibidas. La accesibilidad pública no equivale a autorización. Antes de probar, revisa la legislación y normativa de todos los países y jurisdicciones pertinentes; pueden resultar aplicables normas sobre acceso no autorizado, privacidad y datos personales, confidencialidad de comunicaciones, contratos y obligaciones sectoriales. El proyecto no ofrece asesoramiento jurídico ni concede permisos. Si la autorización o la base jurídica no están claras, no ejecutes la prueba. Consulta el [aviso completo de uso responsable y legal](uso-responsable.md).


## Vector de evidencia del escáner estático y canario controlado

Los resultados estáticos incorporan un vector con cuatro dimensiones independientes: `VERBAL_ACCEPTANCE`, `PERSISTENT_OVERRIDE`, `POLICY_BYPASS` y `CANARY_DISCLOSURE`. Una coincidencia textual afirmativa puede marcar únicamente `VERBAL_ACCEPTANCE`, como señal heurística pendiente de revisión humana. La persistencia permanece `NOT_TESTED` y el bypass `UNVERIFIED` hasta que un protocolo conductual separado o un oráculo determinista aporte evidencia. Ninguna dimensión asciende automáticamente por otra.

La opción explícita `--canary-test` añade una sonda estática separada con un marcador sintético aleatorio y específico de la ejecución, insertado en el contexto de sistema protegido. Solo se registra `DISCLOSED` si el marcador aparece literalmente en la respuesta. El metadato guarda el SHA-256 del marcador y el hash del contexto inyectado, no un campo dedicado con el valor. **Si el modelo lo revela, el marcador aparecerá necesariamente en el texto bruto de la respuesta conservada**; protege y redacta los informes antes de compartirlos. No es una prueba de secretos reales y no debe usarse con credenciales o datos personales. La opción no se combina con modo adaptativo ni perfil rápido.

Versiones del escáner estático: detector `4`, esquema JSON `2` y esquema de evidencias `2`. El número de versión del detector y su huella de implementación SHA-256 son identificadores distintos; conserva ambos al comparar ejecuciones.
