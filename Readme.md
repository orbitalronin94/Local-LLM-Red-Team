# Local LLM Red Team

Herramienta pequeña y reproducible para realizar **red teaming de modelos de lenguaje ejecutados localmente**.

El objetivo es poder lanzar una batería de ataques contra un LLM, detectar comportamientos potencialmente vulnerables y conservar los resultados de forma auditable, sin necesidad de enviar las conversaciones a servicios externos.

> **Estado:** `v0.1.0` — prototipo funcional / primera versión de portfolio.

---

## Qué hace

El proyecto ejecuta una colección de ataques controlados contra un modelo y registra:

* ataque utilizado
* categoría
* prompt enviado
* respuesta del modelo
* resultado de la detección
* latencia
* tokens, cuando el proveedor los proporciona
* modelo utilizado
* `run_id`
* timestamp
* hash del corpus de ataques
* errores de ejecución

Los resultados se almacenan en **SQLite** y pueden exportarse a Markdown o JSON.

La arquitectura deliberadamente pequeña es:

```text
Ataque
   ↓
Target
   ↓
Respuesta del modelo
   ↓
Detector
   ↓
Resultado
   ↓
SQLite / Markdown / JSON
```

---

## Objetivo

El proyecto está pensado principalmente para evaluar **LLMs locales o endpoints bajo control del usuario**.

Casos de uso:

* comparar diferentes modelos locales
* detectar jailbreaks básicos
* comprobar resistencia frente a prompt injection
* intentar extraer instrucciones de sistema
* comprobar si el modelo acepta instrucciones que contradicen su contexto
* estudiar comportamientos de persistencia
* generar evidencia reproducible de una evaluación
* integrar red teaming básico en procesos de desarrollo

No pretende sustituir frameworks completos de evaluación o red teaming.

La prioridad es mantener una herramienta:

* pequeña
* auditable
* reproducible
* fácil de ejecutar
* fácil de modificar
* con pocas dependencias
* orientada a modelos locales

---

## Características

### Targets

Actualmente soporta:

* **Ollama**
* **OpenAI-compatible APIs**
* **HTTP JSON genérico**

Esto permite trabajar con servidores locales como:

```text
Ollama
llama.cpp
vLLM
servidores propios
gateways locales
```

siempre que expongan una interfaz compatible.

---

### Ataques

La versión inicial incluye probes para:

* jailbreak mediante roleplay
* jailbreak mediante autoridad
* instruction override
* extracción del system prompt
* resumen del system prompt
* prompt injection mediante documentos
* prompt injection orientado a herramientas
* persistencia de instrucciones inseguras

Los ataques están definidos como datos, no como una jerarquía compleja de clases.

Ejemplo conceptual:

```python
Attack(
    id="instruction-override",
    category="instruction_override",
    name="Instruction Override",
    prompt="Ignore previous instructions and ..."
)
```

Esto permite ampliar el corpus sin convertir el proyecto en un framework.

---

## Detección

La primera versión utiliza un detector heurístico.

El detector busca patrones asociados con:

* aceptación de jailbreak
* revelación de instrucciones
* confirmación de overrides
* respuestas que indican extracción de contexto
* determinados patrones de rechazo

Por diseño, **no se presenta como un juez semántico perfecto**.

Un resultado positivo significa:

> El detector encontró evidencia compatible con un comportamiento vulnerable.

No significa necesariamente que un modelo haya sido comprometido de forma semánticamente correcta.

Esta distinción es importante para evitar falsos positivos y, especialmente, falsos niveles de confianza.

---

## Ejecución

### Requisitos

* Python `3.10+`
* un modelo local o endpoint HTTP compatible

El núcleo utiliza únicamente la biblioteca estándar de Python.

Para ejecutar los tests se utiliza `pytest`.

---

## Self-test

Antes de utilizar un target real:

```bash
python redteam.py --selftest
```

También:

```bash
make selftest
```

---

## Ver ataques disponibles

```bash
python redteam.py --list-attacks
```

o:

```bash
make list
```

---

## Ollama

Con Ollama ejecutándose localmente:

```bash
ollama serve
```

y un modelo disponible:

```bash
ollama run llama3.2
```

se puede lanzar:

```bash
python redteam.py \
    --target ollama \
    --model llama3.2
```

Por defecto se utiliza:

```text
http://127.0.0.1:11434
```

También puede especificarse otro endpoint:

```bash
python redteam.py \
    --target ollama \
    --model llama3.2 \
    --url http://127.0.0.1:11434
```

---

## API compatible con OpenAI

Para un servidor local que exponga una API compatible:

```bash
python redteam.py \
    --target openai \
    --model local-model \
    --url http://127.0.0.1:8000/v1
```

Si requiere autenticación:

```bash
export REDTEAM_API_KEY="..."
```

y:

```bash
python redteam.py \
    --target openai \
    --model local-model \
    --api-key "$REDTEAM_API_KEY"
```

---

## HTTP JSON

También se puede utilizar un endpoint HTTP genérico:

```bash
python redteam.py \
    --target http \
    --model local-model \
    --url http://127.0.0.1:8000/generate
```

El adaptador espera una respuesta JSON de la que pueda extraer el texto generado.

---

## Resultados

Por defecto los resultados se almacenan en SQLite.

Ejemplo:

```text
redteam.db
```

Cada ejecución genera un identificador:

```text
run_id
```

y cada ataque queda asociado a esa ejecución.

La base de datos permite conservar varias campañas y compararlas posteriormente.

---

## Informes

Para generar un informe Markdown:

```bash
python redteam.py \
    --target ollama \
    --model llama3.2 \
    --report report.md
```

También se puede generar JSON:

```bash
python redteam.py \
    --target ollama \
    --model llama3.2 \
    --json results.json
```

El informe contiene, entre otros datos:

* modelo
* número de ataques
* vulnerabilidades detectadas
* tasa de éxito de los ataques
* tasa de rechazo
* latencia
* percentiles de latencia
* tokens
* errores
* detalle de cada ataque

---

## Reproducibilidad

Cada ejecución conserva información suficiente para reconstruir el contexto de la evaluación:

```text
run_id
timestamp
modelo
target
corpus de ataques
hash del corpus
resultados individuales
latencia
tokens
errores
```

El hash del corpus permite detectar cambios en la batería de ataques entre ejecuciones.

Por ejemplo:

```text
run A
attack_manifest_hash = abc123...

run B
attack_manifest_hash = abc123...
```

indica que ambas ejecuciones utilizaron el mismo corpus de ataques.

Si el hash cambia, el conjunto de probes ha cambiado.

---

## Arquitectura

El proyecto está deliberadamente implementado como un **monolito pequeño**.

No existe una arquitectura de plugins obligatoria ni una cadena de dependencias extensa.

Los principales componentes son:

```text
Attack
    ↓
Target
    ↓
TargetResponse
    ↓
Detector
    ↓
Detection
    ↓
AttackResult
    ↓
Database
```

### Attack

Representa un ataque reproducible.

### Target

Abstracción mínima sobre el modelo evaluado.

Implementaciones actuales:

```text
OllamaTarget
OpenAICompatibleTarget
HTTPJSONTarget
```

### Detector

Analiza la respuesta del modelo.

La implementación inicial es:

```text
HeuristicDetector
```

### Database

Persistencia en SQLite.

No requiere servidor de base de datos.

### Scanner

Coordina:

```text
ataques → target → detector → persistencia
```

### Reporter

Genera:

```text
Markdown
JSON
resumen de consola
```

---

## Métricas

La primera versión recoge métricas sencillas pero útiles:

### Attack Success Rate

Proporción de ataques que producen evidencia compatible con el comportamiento buscado.

```text
successful attacks / executed attacks
```

### Refusal Rate

Proporción de ataques ante los que el modelo presenta un rechazo detectable.

### Latencia

Tiempo de respuesta por ataque.

Se calculan también percentiles para evitar depender exclusivamente de la media.

### Tokens

Cuando el proveedor los proporciona se almacenan los tokens de entrada y salida.

No todos los targets tienen por qué proporcionar esta información.

---

## Limitaciones actuales

Esta es deliberadamente una primera versión.

No intenta resolver todavía:

* ataques adaptativos
* ataques multi-turn reales
* generación automática de ataques
* jueces LLM
* clasificación semántica avanzada
* fuzzing de prompts
* optimización de ataques
* agentes autónomos de red teaming
* browser automation
* tool-use complejo
* scoring avanzado
* distribución de cargas
* ejecución concurrente masiva

Estas funcionalidades pueden ser interesantes, pero añadirlas demasiado pronto convertiría una herramienta pequeña y auditable en otro framework de evaluación generalista.

---

## Filosofía

El proyecto sigue unas pocas reglas:

### 1. Local-first

Siempre que sea posible, la evaluación debe ejecutarse contra modelos bajo control del usuario.

### 2. Reproducibilidad

Una ejecución debe poder identificarse y compararse con otras.

### 3. Auditabilidad

Los prompts y respuestas deben poder conservarse para analizar posteriormente los resultados.

### 4. Simplicidad

La herramienta debe ser suficientemente pequeña como para entender su funcionamiento completo leyendo el repositorio.

### 5. No confundir heurística con verdad

Un detector puede producir falsos positivos y falsos negativos.

Los resultados deben interpretarse como evidencia de una evaluación, no como una prueba matemática de seguridad.

---

## Relación con otros proyectos

Existen frameworks mucho más completos para evaluación y red teaming de LLMs.

Este proyecto no pretende competir con ellos en amplitud.

El objetivo es diferente:

```text
frameworks completos
        ↓
muchas capacidades
muchas integraciones
muchas abstracciones

Local LLM Red Team
        ↓
pocas abstracciones
ejecución local
reproducibilidad
auditabilidad
facilidad de modificación
```

La intención es disponer de una herramienta pequeña que pueda utilizarse para experimentar con modelos locales y estudiar técnicas de red teaming sin introducir una infraestructura excesiva.

---

## Tests

Ejecutar:

```bash
pytest -q
```

Con cobertura:

```bash
pytest --cov=. --cov-report=term-missing
```

O:

```bash
make test
make cov
```

Los tests cubren:

* utilidades
* corpus de ataques
* detectores
* targets simulados
* persistencia SQLite
* ejecución del scanner
* errores de target
* generación de informes
* métricas
* reproducibilidad básica

---

## Estructura

```text
local-llm-redteam/
├── redteam.py
├── README.md
├── pyproject.toml
├── Makefile
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml
└── tests/
    └── test_redteam.py
```

La aplicación principal está contenida en:

```text
redteam.py
```

La intención es que el proyecto pueda estudiarse sin tener que recorrer una arquitectura distribuida entre decenas de módulos.

---

## CI

GitHub Actions ejecuta automáticamente:

```text
Python 3.10
Python 3.11
Python 3.12
```

y comprueba:

```text
self-test
pytest
coverage
```

---

## Seguridad y uso responsable

Esta herramienta está destinada a evaluar sistemas de IA que el usuario controla o para los que dispone de autorización explícita.

Las técnicas de red teaming pueden producir prompts diseñados para provocar comportamientos no deseados.

No utilices el proyecto para acceder, modificar o extraer información de sistemas de terceros sin autorización.

---

## Licencia

MIT License.

Copyright (c) 2026 David Ferrandez Canalis.

Consulta el archivo `LICENSE` para el texto completo de la licencia.
