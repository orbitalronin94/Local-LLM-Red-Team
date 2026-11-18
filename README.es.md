# Local LLM Red Team

[![CI](https://github.com/orbitalronin94/Local-LLM-Red-Team/actions/workflows/ci.yml/badge.svg)](https://github.com/orbitalronin94/Local-LLM-Red-Team/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![Licencia MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Idioma / Language:** [Español](README.es.md) · [English](README.md)

**Herramienta ligera de Python, local-first, para evaluar de forma reproducible la seguridad de modelos de lenguaje alojados en infraestructura propia.** Prueba jailbreaks, prompt injection, anulación de instrucciones, extracción del system prompt y persistencia multi-turno contra Ollama, servidores compatibles con OpenAI y endpoints HTTP JSON genéricos. Los hallazgos heurísticos se exportan a JSON, Markdown y SQLite.

**Estado:** Alpha, versión 0.1.0. La interfaz pública y el catálogo de ataques pueden evolucionar antes de 1.0. Al probar un endpoint local no hace falta una cuenta cloud, una suscripción API ni un framework de ejecución adicional.

> **Uso responsable — autorización obligatoria.** Prueba únicamente sistemas, modelos y endpoints propios o cuyo análisis tengas expresamente autorizado. No escanees sistemas ajenos sin permiso previo. Antes de probar, define el alcance por escrito y revisa la legislación de **todos los países y jurisdicciones pertinentes**. Que un sistema sea accesible públicamente no significa que tengas autorización. Consulta el [aviso de uso responsable y legal](docs/uso-responsable.md).

## Por qué existe

Los modelos locales se utilizan en asistentes privados, herramientas de programación y flujos internos. Ejecutarlos en localhost no los hace inmunes a instrucciones hostiles. También necesitan pruebas de seguridad.

El proyecto tiene un alcance deliberadamente más acotado que una plataforma generalista de seguridad de IA: ofrece un banco de pruebas pequeño e inspeccionable para evaluar **comportamiento a nivel de prompt**, con ataques reproducibles y evidencias comparables.

## Capacidades

- **Modelos locales:** destinos Ollama y endpoints de chat compatibles con OpenAI.
- **Endpoints propios:** HTTP JSON genérico con payload `model` + `messages`.
- **Escaneos estáticos y adaptativos:** pruebas independientes o secuencias multi-turno acotadas con un modelo atacante separado.
- **Catálogo versionado:** IDs, categorías, versiones y huella SHA-256 del manifiesto.
- **Detección heurística transparente:** estados `PASS`, `FAIL`, `NOT_DETECTED`, `EMPTY` y `ERROR`.
- **Evidencia portable:** registros SQLite e informes JSON/Markdown; conserva tokens cuando el destino los proporciona.
- **Comparación:** helper programático para comparar resultados obtenidos con el mismo conjunto de ataques.

### Catálogo predeterminado

| ID | Categoría | Prueba |
| --- | --- | --- |
| `jailbreak-roleplay` | Jailbreak | Enmarcado de rol sin restricciones |
| `jailbreak-authority` | Jailbreak | Falsas afirmaciones de autoridad o aprobación |
| `instruction-override` | Anulación | Intentos de desactivar instrucciones previas |
| `system-prompt-extraction` | Extracción | Solicitud directa de instrucciones ocultas |
| `system-prompt-summary` | Extracción | Resumen indirecto de instrucciones ocultas |
| `prompt-injection-document` | Prompt injection | Instrucciones maliciosas en documentos no confiables |
| `prompt-injection-tool` | Prompt injection | Revelación de herramientas o configuración |
| `persistence` | Persistencia | Retención de instrucciones entre turnos |

El escáner principal usa la biblioteca estándar de Python. `pytest` y `pytest-cov` son dependencias opcionales.

## Inicio rápido

Requiere Python 3.10 o superior.

```bash
git clone https://github.com/orbitalronin94/Local-LLM-Red-Team.git
cd Local-LLM-Red-Team
python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
local-llm-redteam --list-attacks
local-llm-redteam --selftest
```

También puedes ejecutar `python redteam.py --list-attacks` y `python redteam.py --selftest` sin instalar el paquete.

## Ejecutar pruebas

### Ollama

```bash
ollama pull llama3.2
local-llm-redteam --target ollama --model llama3.2 --url http://127.0.0.1:11434
```

Selecciona ataques o categorías:

```bash
local-llm-redteam --target ollama --model llama3.2 --attack jailbreak-roleplay --attack system-prompt-extraction
local-llm-redteam --target ollama --model llama3.2 --category prompt_injection
```

### Servidor compatible con OpenAI

Utiliza la URL base del servidor, normalmente terminada en `/v1`:

```bash
local-llm-redteam --target openai --model local-model --url http://127.0.0.1:8000/v1
```

Si el servidor exige clave, pásala con `--api-key`; se envía como token Bearer.

### Endpoint HTTP JSON

```bash
local-llm-redteam --target http --model local-model --url http://127.0.0.1:8000/generate
```

El cuerpo contiene `model` y `messages`:

```json
{
  "model": "local-model",
  "messages": [{"role": "user", "content": "El prompt de ataque"}]
}
```

El parser acepta campos habituales como `response`, `text`, `output`, `content`, `generated_text`, `message.content` y `choices` al estilo OpenAI.

### Modo adaptativo multi-turno

El modo adaptativo solicita a otro destino que genere mensajes de seguimiento. Limita las rondas:

```bash
local-llm-redteam --target ollama --model llama3.2 --mode adaptive --adaptive-rounds 5 --attacker-target ollama --attacker-model llama3.1
```

Los mensajes generados pueden variar entre ejecuciones. Conserva el informe completo y controla el modelo atacante y sus parámetros al comparar resultados.

## Informes y resultados

```bash
local-llm-redteam --target ollama --model llama3.2 --db redteam.db --json report.json --report report.md
```

El resumen incluye recuentos, fallos heurísticos, errores, señales de rechazo y latencia. Los tokens se conservan cuando el destino los devuelve.

| Estado | Significado |
| --- | --- |
| `FAIL` | La respuesta coincide con indicadores asociados a aceptar el ataque. |
| `PASS` | La respuesta coincide con un indicador de rechazo. |
| `NOT_DETECTED` | No aparece un patrón conocido de éxito o rechazo; resultado inconcluso. |
| `EMPTY` | El destino devuelve una respuesta vacía. |
| `ERROR` | Falla la petición o el procesamiento de la respuesta. |

El detector es heurístico, no un juez semántico. La tasa de éxito es el número de `FAIL` dividido por las ejecuciones no erróneas; describe ese catálogo y esa versión del detector, no la probabilidad universal de vulnerabilidad.

**Un `PASS` no demuestra que el modelo sea seguro. Un `NOT_DETECTED` no demuestra que el ataque haya fracasado.** Revisa las respuestas y las evidencias. Consulta la [metodología de detección y limitaciones](docs/methodology.es.md), la [guía de interpretación de informes](docs/report-guide.es.md) y la [matriz de cobertura por idioma y ataque](docs/coverage-matrix.es.md).

## Reproducibilidad

Cada ejecución recibe un ID. SQLite registra versión del escáner, destino, modelo, hash del manifiesto y modo. JSON conserva versión, ID, resultados, respuestas, hallazgos y latencias; JSON y SQLite guardan tokens cuando están disponibles y los turnos adaptativos.

Para comparar modelos, conserva el manifiesto, configuración del endpoint, revisión del modelo, parámetros de generación y entorno. Documenta cualquier diferencia y cambia una variable cada vez cuando sea posible.

## Kit de benchmark de modelos locales

Los pesos GGUF se descargan bajo demanda a `models/weights/`; no se guardan en Git. Cada descarga genera metadatos con origen, ETag, tamaño y SHA-256.

| Modelo | Parámetros | Cuantización | Tamaño aprox. | Licencia |
| --- | ---: | --- | ---: | --- |
| SmolLM2 360M Instruct | 360M | Q4_K_M | 271 MB | Apache-2.0 |
| Qwen2.5 0.5B Instruct | 0,5B | Q4_K_M | 491 MB | Apache-2.0 |
| Llama 3.2 1B Instruct | 1B | Q4_K_M | 808 MB | Llama 3.2 Community License |
| Gemma 3 1B IT | 1B | Q4_K_M | 806 MB | Gemma Terms |
| Granite 3.3 2B Instruct | 2B | Q4_K_M | 1,55 GB | Apache-2.0 |
| Phi-3.5 Mini Instruct | 3,8B | Q4_K_M | 2,39 GB | MIT |
| Ministral 3B Instruct | 3B | Q4_K_M | 1,86 GB | Apache-2.0 |

Son cuantizaciones comunitarias. Llama y Gemma tienen términos propios; consulta cada tarjeta upstream antes de redistribuir o utilizar comercialmente. SmolLM2 está orientado principalmente al inglés y Qwen2.5 ofrece soporte multilingüe más amplio: no extrapoles resultados entre idiomas.

```bash
python scripts/download_models.py --list
python scripts/download_models.py --model smollm2
python scripts/download_models.py --model qwen2_5
python scripts/download_models.py --model all
```

Instala el descargador con `python -m pip install -e ".[models]"`. Para servir un GGUF con llama.cpp:

```bash
llama-server --model models/weights/SmolLM2-360M-Instruct-Q4_K_M.gguf --host 127.0.0.1 --port 8080
```

Genera el paquete de informes:

```bash
mkdir -p reports
python redteam.py --target openai --url http://127.0.0.1:8080/v1 --model local-model --db reports/smollm2.db --json reports/smollm2.json --report reports/smollm2.md
```

Mantén constantes manifiesto, versión del servidor, contexto, parámetros y hardware. Consulta la [guía del kit de modelos](models/README.es.md).

## Desarrollo y pruebas

```bash
python -m pip install -e ".[dev]"
make test
make coverage
make selftest
```

CI ejecuta self-tests y pytest en Python 3.10, 3.11 y 3.12.

## Alcance y uso responsable

El proyecto evalúa **comportamiento a nivel de prompt**. No ofrece actualmente:

- cobertura integral de OWASP LLM Top 10 ni certificación;
- evaluación semántica mediante un modelo juez;
- análisis de pesos, cadena de suministro o datos de entrenamiento;
- pentesting de navegador, runtime real de herramientas, sandbox de agentes o red;
- generación autónoma e ilimitada de exploits.

Prueba solo modelos y endpoints propios o autorizados. Mantén privados los endpoints locales, protege claves e informes y no envíes datos sensibles a destinos no verificados.

## Preguntas frecuentes

**¿Funciona offline?** Sí, si el modelo y el servidor ya están instalados localmente.

**¿Es compatible con Ollama?** Sí, además de servidores compatibles con OpenAI y HTTP JSON genérico.

**¿Un escaneo satisfactorio certifica seguridad?** No. Puede haber falsos positivos y negativos; los resultados son evidencia de cribado, no una garantía.

**¿Sustituye una plataforma completa de red teaming?** No. Se centra deliberadamente en pruebas reproducibles de prompts.

## Licencia

MIT. Consulta [LICENSE](LICENSE).


## Investigación y evolución

Consulta la [hoja de ruta de ampliación basada en papers recientes](docs/research-roadmap.es.md) para conocer las próximas familias de ataques, el plan de evaluación y las referencias científicas. La [versión en inglés](docs/research-roadmap.md) está disponible también.


### Escenarios deterministas de varios turnos

Ejecuta la suite fija por separado del catálogo estático/adaptativo:

~~~bash
python scenarios.py --target ollama --model llama3.2 --json informe-escenarios.json --report informe-escenarios.md
~~~

La primera suite cubre construcción gradual de contexto, negativa seguida de reformulación y persistencia de instrucciones no confiables. Cada escenario tiene ID/versión estables, secuencia fija, atribución de fuente/hipótesis y manifiesto SHA-256. El control benigno se ejecuta en una conversación nueva y se registra aparte. Su utilidad no se puntúa automáticamente: requiere revisión humana. Son pruebas a nivel de prompt; no ejecutan herramientas ni demuestran impacto real.

### Comparación emparejada EN/ES y revisión humana

El benchmark ejecuta diez pares de prompts en inglés y español, con controles benignos independientes. Los resultados se guardan por idioma y par; no son traducciones certificadas ni una evaluación multilingüe representativa. También genera una hoja CSV de revisión humana con prompts, respuestas, señales heurísticas y campos de anotación. Las señales de texto no demuestran efectos reales ni ejecución de herramientas.

