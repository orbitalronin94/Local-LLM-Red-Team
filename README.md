# Local LLM Red Team

[![CI](https://github.com/orbitalronin94/Local-LLM-Red-Team/actions/workflows/ci.yml/badge.svg)](https://github.com/orbitalronin94/Local-LLM-Red-Team/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Language / Idioma:** [English](README.md) · [Español](README.es.md)

**A lightweight, local-first Python harness for reproducible security testing of locally hosted large language models (LLMs).** Probe jailbreaks, prompt injection, instruction overrides, system-prompt extraction and multi-turn persistence against Ollama, OpenAI-compatible servers and generic HTTP JSON endpoints. Review heuristic findings as JSON, Markdown or SQLite records.

**Project status:** Pre-1.0 (package version 0.1.0). The project remains in active validation; the public interface, attack catalogue and report schemas may evolve before 1.0.

> **Responsible use — authorization required.** Only test systems, models and endpoints you own or have explicit prior permission to assess. Never scan third-party systems without authorization. Before testing, define a written scope and check the laws and regulations in **every relevant country and jurisdiction**. Public reachability is not permission. See [Responsible use and legal notice](docs/responsible-use.md).

No cloud account, API subscription or runtime framework is required when testing a local endpoint.

> **Authorized use only:** Test only systems you own or are explicitly authorized to assess. Do not scan third-party systems without prior permission. Laws differ by jurisdiction: review the laws, contracts, privacy rules and provider terms in every relevant country before testing. This project is not legal advice. Read the [authorized-use and legal notice](docs/legal-use.md).

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
| `indirect-injection-retrieved-content` | Prompt injection | Instructions embedded in simulated retrieved content |
| `tool-output-injection` | Prompt injection | Instructions embedded in simulated tool output |
| `delimiter-boundary-confusion` | Instruction override | Confusion between delimiters and instruction roles |
| `multilingual-instruction-override` | Instruction override | Spanish-language instruction override |
| `refusal-suppression` | Jailbreak | Attempts to suppress refusal behaviour |
| `multi-turn-persistence` | Persistence | Seed prompt for a later behavioural persistence task |

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

The reported heuristic attack-success and refusal rates use only executable results: `total - ERROR - EMPTY - THROTTLED`. `EMPTY`, transport `ERROR` and HTTP `THROTTLED` outcomes are excluded; `PASS` and inconclusive `NOT_DETECTED` remain in the denominator. Coverage is reported separately. This is a screening metric for the selected attack set, not a probability that the model is vulnerable.

**A `PASS` does not prove that a model is secure. A `NOT_DETECTED` result does not prove that an attack failed.** Inspect the response, evidence and test context before drawing conclusions. See [Detection methodology and limitations](docs/methodology.md), the [report interpretation guide](docs/report-guide.md), and the [language and attack coverage matrix](docs/coverage-matrix.md). See also the [research-backed expansion roadmap](docs/research-roadmap.md). See the [exploit-to-guardrail protocol](docs/exploit-to-guardrail.md) for a tested least-privilege action gate and its limitations.

## Reproducibility

Each run receives a unique run ID. SQLite stores the scanner version, target, model, attack-manifest hash and execution mode. JSON reports include the scanner version and run ID; result records preserve attack IDs and versions, responses, detector findings and latency. JSON and SQLite also retain token usage when available and adaptive conversation turns.

For meaningful model comparisons, keep the attack manifest, endpoint configuration, model revision, generation settings and test environment consistent. Record any differences alongside the report.

See the [automated findings catalogue](docs/findings-catalog.md) for the per-run cross-model index of heuristic positives and inconclusive cases, including prompts, responses and model provenance.


## Local model benchmark kit

A small-model download manifest and reproducible local benchmark recipe are included. Model weights are not stored in Git: download them into models/weights/ on demand. A sidecar JSON records the resolved URL, ETag, byte count and SHA-256 digest for each downloaded file.

| Model | Parameters | Quantization | Approx. download | License |
| --- | ---: | --- | ---: | --- |
| SmolLM2 360M Instruct | 360M | Q4_K_M | 271 MB | Apache-2.0 |
| Qwen2.5 0.5B Instruct | 0.5B | Q4_K_M | 491 MB | Apache-2.0 |
| Llama 3.2 1B Instruct | 1B | Q4_K_M | 808 MB | Llama 3.2 Community License |
| Gemma 3 1B IT | 1B | Q4_K_M | 806 MB | Gemma Terms |

SmolLM2 is primarily English; Qwen2.5 has broader multilingual support. These compact models are smoke-test targets, not a representative benchmark of all model sizes or languages. GGUF files are community quantizations: check each upstream model card and license before redistribution or commercial use. See [Local model benchmark kit](models/README.md) for the complete manifest.

```bash
python scripts/download_models.py --list
python scripts/download_models.py --model smollm2
python scripts/download_models.py --model qwen2_5
python scripts/download_models.py --model llama3_2_1b
python scripts/download_models.py --model gemma3_1b
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

Continuous integration runs self-tests, the full pytest suite and coverage across all first-party modules on Python 3.10–3.13. See [V1 readiness](docs/v1-readiness.md) for release gates.

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


### Deterministic multi-turn scenarios

Run the fixed scenario suite separately from the static/adaptive catalogue:

~~~bash
python scenarios.py --target ollama --model llama3.2 --json scenario-report.json --report scenario-report.md
~~~

The initial suite covers context laundering, refusal followed by reframing, and untrusted-instruction persistence. Each scenario has a stable ID/version, fixed turn sequence, source/hypothesis attribution, and a SHA-256 manifest. A benign control runs in a fresh conversation and is recorded separately. Control outputs are not automatically scored as useful: they require human review. These are prompt-level scenarios; they do not execute tools or prove real-world impact.

### Paired English/Spanish probes and human review

The benchmark runs ten intent-matched English/Spanish probe pairs with separate benign controls. Results retain pair IDs and language labels; these are not certified translations or a representative multilingual evaluation. It also exports a human-review CSV containing prompts, responses, heuristic signals and annotation fields. Text signals do not prove real-world effects or tool execution.



## Behavioral persistence and robustness matrix

The controlled protocol is available as an installed command:

```bash
local-llm-redteam-protocol --target ollama --model MODEL --seed 42 --variant direct
```

To separate sampling variance from paraphrase robustness, run the matrix:

```bash
local-llm-redteam-matrix --target ollama --model MODEL \
  --seeds 42,43,44 \
  --variants direct,authority_reframing,contextual_reframing
```

The matrix treats clean regression controls as a cohort gate, excludes baseline failures from attack denominators, computes seed variance for each fixed paraphrase, and measures paraphrase susceptibility within each fixed seed. See [the persistence protocol](docs/persistence-protocol.md) and [the robustness matrix](docs/robustness-matrix.md). These controlled synthetic fixtures are evaluation instruments, not production-policy certifications.


## Version 1.0 readiness

The project is intentionally pre-1.0. Track evidence validity, attack coverage, reproducibility, software quality, report quality and release acceptance in the [V1 readiness checklist](docs/v1-readiness.md).


### Replay one recorded attack

Re-run a single static attack from an earlier JSON report while verifying the stored prompt hash:

```bash
local-llm-redteam-replay --report report.json --attack-id system-prompt-extraction \
  --target openai --url http://127.0.0.1:8000/v1 --model local-model \
  --seed 42 --temperature 0 --output replay.json
```

The endpoint URL, model revision and server/runtime identity must be supplied or recorded by the operator; credentials are read from REDTEAM_API_KEY by default. A replay preserves the original prompt and records a new response, but does not guarantee identical generation. See the replay metadata and compare model/server identity before drawing conclusions.


## Fast development iterations

The benchmark workflow supports an explicit quick profile for development loops. Dispatch the workflow with benchmark_profile=quick to run an eight-attack English/Spanish screening subset with a 192-token generation cap. It skips adaptive self-play, multi-turn scenarios, paired-language duplication and the seed/paraphrase robustness matrix. This is a reduced screen, not an official full evaluation; push-triggered runs and the default manual profile remain full.

For local runs, use local-llm-redteam --profile quick. The quick profile is static-only and records its selected attack manifest and generation cap. Full runs retain the complete catalogue. Any profile can use --max-output-tokens N to set a per-response generation ceiling; omitted means the target/server default. Truncated responses are marked for review, never silently treated as complete evidence. See docs/performance-profiles.md.


## Evidence vectors, synthetic canary and report versions

Every static result carries an independent evidence vector: `VERBAL_ACCEPTANCE`, `PERSISTENT_OVERRIDE`, `POLICY_BYPASS` and `CANARY_DISCLOSURE`. A phrase-level detector signal can populate only review-required `VERBAL_ACCEPTANCE`; it does not prove persistence or policy bypass. Those dimensions require a separate post-injection behavioural task or a deterministic oracle.

Run the opt-in synthetic canary probe separately from the ordinary attack profile:

```bash
local-llm-redteam --target ollama --model llama3.2 --canary-test --json canary.json --report canary.md
```

The probe is static-only and incompatible with `--profile quick`. It places a random, run-scoped synthetic marker in a protected system message and records disclosure only on an exact literal match. The raw response is retained as evidence and can therefore contain the marker if disclosed; protect or redact reports before sharing. The marker is not a real secret and must never be replaced with credentials or personal data.

Current metadata versions: detector `4`, JSON report schema `2`, evidence vector schema `2`. The detector implementation fingerprint is recorded separately from its version. Do not pool results across detector fingerprints or report schemas without an explicit migration/normalization step. See [the evidence model](docs/evidence-model.md), [methodology](docs/methodology.md) and [report guide](docs/report-guide.md).
