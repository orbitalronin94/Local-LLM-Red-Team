# Local LLM Red Team

[![CI](https://github.com/orbitalronin94/Local-LLM-Red-Team/actions/workflows/ci.yml/badge.svg)](https://github.com/orbitalronin94/Local-LLM-Red-Team/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Language / Idioma:** [English](README.md) · [Español](README.es.md)

**Language / Idioma:** [English](README.md) · [Español](README.es.md)

**A lightweight, local-first Python harness for reproducible security testing of locally hosted large language models (LLMs).** Probe jailbreaks, prompt injection, instruction overrides, system-prompt extraction and multi-turn persistence against Ollama, OpenAI-compatible servers and generic HTTP JSON endpoints. Review heuristic findings as JSON, Markdown or SQLite records.

**Project status:** Alpha, version 0.1.0. The public interface and attack catalogue may evolve before 1.0.

No cloud account, API subscription or runtime framework is required when testing a local endpoint.

## Why this project exists

Local LLMs are increasingly used for private assistants, coding tools and internal workflows. They still need security testing: a model running on localhost can mishandle hostile instructions just as a hosted model can.

Local LLM Red Team is deliberately narrower than a general-purpose AI security platform. It provides a small, inspectable test harness for **prompt-level model behaviour**, with repeatable attack definitions and evidence that can be compared across models.

## Capabilities

- **Local model testing:** Ollama and OpenAI-compatible chat-completion endpoints.
- **Custom endpoints:** generic HTTP JSON targets using a `model` plus `messages` request payload.
- **Static and adaptive scans:** independent probes or bounded multi-turn tests with a separate attacker model.
- **Versioned attack catalogue:** stable attack IDs, categories, versions and a SHA-256 attack-manifest fingerprint.
- **Transparent heuristic detection:** explicit `PASS`, `FAIL`, `NOT_DETECTED`, `EMPTY` and `ERROR` outcomes.
- **Portable evidence:** SQLite run records plus JSON and Markdown reports; JSON and SQLite preserve token counts when the target supplies them.
- **Model comparison:** a programmatic helper for comparing result sets produced against the same attack set.

### Default attack catalogue

| Attack ID | Category | Probe |
| --- | --- | --- |
| `jailbreak-roleplay` | Jailbreak | Unrestricted role-play framing |
| `jailbreak-authority` | Jailbreak | False authority and approval claims |
| `instruction-override` | Instruction override | Attempts to disable previous instructions |
| `system-prompt-extraction` | System extraction | Direct request for hidden system instructions |
| `system-prompt-summary` | System extraction | Indirect request to summarize hidden instructions |
| `prompt-injection-document` | Prompt injection | Malicious instructions embedded in untrusted document text |
| `prompt-injection-tool` | Prompt injection | Tool/configuration disclosure framing |
| `persistence` | Persistence | Attempts to retain unsafe instructions across turns |

The core scanner uses the Python standard library. `pytest` and `pytest-cov` are optional development dependencies.

## Quick start

Requires Python 3.10 or newer.

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

You can also run the script directly without installing the package:

```bash
python redteam.py --list-attacks
python redteam.py --selftest
```

## Run a scan

### Ollama

Start Ollama and make sure the model is available locally:

```bash
ollama pull llama3.2

local-llm-redteam \
  --target ollama \
  --model llama3.2 \
  --url http://127.0.0.1:11434
```

Run selected attacks or one category:

```bash
local-llm-redteam \
  --target ollama \
  --model llama3.2 \
  --attack jailbreak-roleplay \
  --attack system-prompt-extraction

local-llm-redteam \
  --target ollama \
  --model llama3.2 \
  --category prompt_injection
```

### OpenAI-compatible local server

The target uses the chat-completions endpoint. The base URL can be the server's `/v1` URL:

```bash
local-llm-redteam \
  --target openai \
  --model local-model \
  --url http://127.0.0.1:8000/v1
```

If the local server requires a key, pass `--api-key`. The key is sent as a bearer token to that endpoint.

### Generic HTTP JSON endpoint

```bash
local-llm-redteam \
  --target http \
  --model local-model \
  --url http://127.0.0.1:8000/generate
```

The request body contains `model` and `messages`:

```json
{
  "model": "local-model",
  "messages": [
    {"role": "user", "content": "The attack prompt"}
  ]
}
```

The response parser accepts common text fields such as `response`, `text`, `output`, `content`, `generated_text`, `message.content` and OpenAI-style `choices`.

### Adaptive multi-turn testing

Adaptive mode asks a separate attacker target to propose follow-up messages. Keep the number of rounds bounded:

```bash
local-llm-redteam \
  --target ollama \
  --model llama3.2 \
  --mode adaptive \
  --adaptive-rounds 5 \
  --attacker-target ollama \
  --attacker-model llama3.1
```

Adaptive scans are exploratory: the attacker model's generated prompts can vary between runs. The initial attack manifest remains identifiable, but the generated follow-up sequence should be retained as part of the run evidence.

## Results and reports

Persist a run to SQLite and export both machine-readable and human-readable reports:

```bash
local-llm-redteam \
  --target ollama \
  --model llama3.2 \
  --db redteam.db \
  --json report.json \
  --report report.md
```

The summary includes attack counts, heuristic failures, execution errors, refusal signals and latency statistics. Token counts are preserved in JSON and SQLite when the target returns them.

### Understanding detection results

The detector is intentionally heuristic; it is not a semantic LLM judge.

| Status | Meaning |
| --- | --- |
| `FAIL` | The response matched one or more indicators associated with accepting the tested attack. |
| `PASS` | The response matched a refusal indicator for the tested prompt. |
| `NOT_DETECTED` | No known success or refusal pattern was detected. This is inconclusive, not proof of safety. |
| `EMPTY` | The target returned an empty response. |
| `ERROR` | The target request or response handling failed. |

The reported attack-success rate is the number of heuristic `FAIL` results divided by completed, non-error executions. It is a screening metric for this attack set, not a probability that the model is vulnerable.

**A `PASS` does not prove that a model is secure. A `NOT_DETECTED` result does not prove that an attack failed.** Inspect the response, evidence and test context before drawing conclusions. See [Detection methodology and limitations](docs/methodology.md).

## Reproducibility

Each run receives a unique run ID. SQLite stores the scanner version, target, model, attack-manifest hash and execution mode. JSON reports include the scanner version and run ID; result records preserve attack IDs and versions, responses, detector findings and latency. JSON and SQLite also retain token usage when available and adaptive conversation turns.

For meaningful model comparisons, keep the attack manifest, endpoint configuration, model revision, generation settings and test environment consistent. Record any differences alongside the report.


## Local model benchmark kit

A small-model download manifest and reproducible local benchmark recipe are included. Model weights are not stored in Git: download them into models/weights/ on demand. A sidecar JSON records the resolved URL, ETag, byte count and SHA-256 digest for each downloaded file.

| Model | Parameters | Quantization | Approx. download | License |
| --- | ---: | --- | ---: | --- |
| SmolLM2 360M Instruct | 360M | Q4_K_M | 271 MB | Apache-2.0 |
| Qwen2.5 0.5B Instruct | 0.5B | Q4_K_M | 491 MB | Apache-2.0 |
| Llama 3.2 1B Instruct | 1B | Q4_K_M | 808 MB | Llama 3.2 Community License |
| Gemma 3 1B IT | 1B | Q4_K_M | 806 MB | Gemma Terms |
| Granite 3.3 2B Instruct | 2B | Q4_K_M | 1.55 GB | Apache-2.0 |
| Phi-3.5 Mini Instruct | 3.8B | Q4_K_M | 2.39 GB | MIT |
| Ministral 3B Instruct | 3B | Q4_K_M | 1.86 GB | Apache-2.0 |

SmolLM2 is primarily English; Qwen2.5 has broader multilingual support. These compact models are smoke-test targets, not a representative benchmark of all model sizes or languages. GGUF files are community quantizations: check each upstream model card and license before redistribution or commercial use. See [Local model benchmark kit](models/README.md) for the complete manifest.

```bash
python scripts/download_models.py --list
python scripts/download_models.py --model smollm2
python scripts/download_models.py --model qwen2_5
python scripts/download_models.py --model all
```

Serve a downloaded GGUF with a local llama.cpp installation:

```bash
llama-server --model models/weights/SmolLM2-360M-Instruct-Q4_K_M.gguf --host 127.0.0.1 --port 8080
```

Then generate a report bundle:

```bash
mkdir -p reports
python redteam.py --target openai --url http://127.0.0.1:8080/v1 --model local-model --db reports/smollm2.db --json reports/smollm2.json --report reports/smollm2.md
```

Repeat with Qwen2.5 and distinct report names. Keep the attack manifest, inference server version, context size, generation settings and hardware consistent. Record unavoidable differences. See [Local model benchmark kit](models/README.md) for details and limitations.

## Development and tests

```bash
python -m pip install -e ".[dev]"
make test
make coverage
make selftest
```

Continuous integration runs the self-tests and pytest suite on Python 3.10, 3.11 and 3.12.

## Scope and responsible use

This project evaluates **prompt-level behaviour**. It does not currently provide:

- comprehensive OWASP LLM Top 10 coverage or a compliance certification;
- semantic grading by a separate judge model;
- model-weight, supply-chain or training-data analysis;
- browser, tool-execution, agent sandbox or network penetration testing;
- autonomous exploit generation or an unrestricted attack agent.

Only test models and endpoints that you own or are explicitly authorized to assess. Keep local inference endpoints bound to trusted interfaces, protect API keys and reports, and avoid sending sensitive prompts to endpoints you have not verified.

## Frequently asked questions

**Does it work offline?** Yes, when the selected model and inference server are already installed locally. No cloud service is needed for Ollama or another local endpoint.

**Does it support Ollama?** Yes. Ollama is a first-class target, alongside OpenAI-compatible and generic HTTP JSON endpoints.

**Does a passing scan certify a model as safe?** No. The detector uses transparent patterns and can produce false positives and false negatives. Treat results as triage evidence, not a security guarantee.

**Is this a replacement for a full AI red-teaming platform?** No. It is intentionally small and focused on repeatable prompt-level probes.

## Resumen en español

Local LLM Red Team es una herramienta ligera de Python para realizar **pruebas de seguridad y red teaming de modelos de lenguaje locales**. Ejecuta ataques reproducibles de jailbreak, prompt injection, anulación de instrucciones, extracción del system prompt y persistencia contra Ollama, servidores compatibles con la API de OpenAI y endpoints HTTP JSON.

Guarda resultados en SQLite y genera informes JSON y Markdown. El detector es heurístico: permite identificar señales y comparar ejecuciones, pero no certifica la seguridad del modelo. Está diseñado para auditorías autorizadas, reproducibles y ejecutables en infraestructura local.

## License

MIT. See [LICENSE](LICENSE).
