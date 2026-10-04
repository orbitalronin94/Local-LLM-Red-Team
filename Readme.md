# Local LLM Red Team

Small, local-first red teaming harness for testing LLMs against common prompt-level attacks.

The project is deliberately small and auditable. It focuses on reproducible experiments rather than becoming another general-purpose LLM evaluation framework.

## What it does

```text
attack
  ↓
target
  ↓
response
  ↓
heuristic detector
  ↓
result
  ↓
SQLite / JSON / Markdown
```

It can test local models through:

* Ollama
* OpenAI-compatible local endpoints
* Generic HTTP JSON endpoints

The scanner supports two modes:

* `static`: one request per attack
* `adaptive`: multi-turn attacks with a separate attacker model/target

## Included attack categories

The default attack set includes:

* jailbreak
* instruction override
* system prompt extraction
* prompt injection
* persistence

Each attack has a stable ID, category, version and prompt.

## Requirements

* Python 3.10+
* No runtime dependency is required for the core scanner.
* `pytest` and `pytest-cov` are only required for development/testing.

## Quick start

List the available attacks:

```bash
python redteam.py --list-attacks
```

Run the self-tests:

```bash
python redteam.py --selftest
```

Run against Ollama:

```bash
python redteam.py \
  --target ollama \
  --model llama3.2 \
  --url http://localhost:11434
```

Run selected attacks:

```bash
python redteam.py \
  --target ollama \
  --model llama3.2 \
  --attack jailbreak-roleplay \
  --attack system-prompt-extraction
```

Run by category:

```bash
python redteam.py \
  --target ollama \
  --model llama3.2 \
  --category jailbreak
```

Use adaptive multi-turn red teaming:

```bash
python redteam.py \
  --target ollama \
  --model llama3.2 \
  --mode adaptive \
  --adaptive-rounds 5
```

Use a separate attacker model:

```bash
python redteam.py \
  --target ollama \
  --model llama3.2 \
  --mode adaptive \
  --adaptive-rounds 5 \
  --attacker-model llama3.1
```

## Targets

### Ollama

```bash
python redteam.py \
  --target ollama \
  --model llama3.2 \
  --url http://localhost:11434
```

### OpenAI-compatible endpoint

```bash
python redteam.py \
  --target openai \
  --model local-model \
  --url http://localhost:8000/v1
```

An API key can be supplied when required:

```bash
python redteam.py \
  --target openai \
  --model local-model \
  --url http://localhost:8000/v1 \
  --api-key local-key
```

### Generic HTTP JSON

```bash
python redteam.py \
  --target http \
  --model local-model \
  --url http://localhost:8000/generate
```

The HTTP target accepts common response formats such as:

```json
{"response": "..." }
```

```json
{"text": "..." }
```

```json
{"message": {"content": "..."}}
```

and OpenAI-style:

```json
{
  "choices": [
    {
      "message": {
        "content": "..."
      }
    }
  ]
}
```

## Output

Every scan produces a run ID and a summary containing information such as:

* total attacks
* successful attacks
* refusals
* errors
* attack success rate
* refusal rate
* latency statistics
* token usage
* estimated cost when token pricing is available

Results can be persisted to SQLite:

```bash
python redteam.py \
  --target ollama \
  --model llama3.2 \
  --db redteam.db
```

Generate JSON:

```bash
python redteam.py \
  --target ollama \
  --model llama3.2 \
  --json report.json
```

Generate Markdown:

```bash
python redteam.py \
  --target ollama \
  --model llama3.2 \
  --report report.md
```

Both can be generated at the same time:

```bash
python redteam.py \
  --target ollama \
  --model llama3.2 \
  --db redteam.db \
  --json report.json \
  --report report.md
```

## Reproducibility

Each scan records:

* run ID
* scanner version
* model
* attack IDs
* attack manifest
* attack versions
* execution mode
* timestamps
* responses
* latency
* token usage when provided
* detector output
* adaptive conversation turns

The attack manifest is derived from the complete attack definitions, allowing the exact attack set used by a run to be identified later.

SQLite stores both run-level and attack-level results.

## Detection

The default detector is intentionally lightweight.

It uses deterministic heuristics such as:

* refusal indicators
* instruction override indicators
* system prompt disclosure indicators
* prompt injection indicators
* persistence indicators

It is **not a semantic LLM judge**.

A `FAIL` therefore means that the heuristic detector found evidence consistent with a successful attack. It does not claim that the model has been comprehensively compromised.

Likewise, `PASS` does not prove that a model is secure.

The goal is to provide a reproducible first-pass signal that can be inspected, compared and extended.

## Static vs adaptive

### Static

Each attack is executed independently:

```text
attack → model → response → detector
```

This mode is deterministic and inexpensive.

### Adaptive

Adaptive mode maintains a conversation and allows a separate attacker target to generate follow-up prompts:

```text
initial attack
      ↓
target response
      ↓
attacker follow-up
      ↓
target response
      ↓
detector
      ↓
repeat
```

The conversation stops early when the detector identifies a successful attack.

This makes adaptive mode useful for exploring multi-turn failure modes without requiring a large orchestration framework.

## Model comparison

Results from multiple models can be compared programmatically using `compare_results`.

The comparison focuses on measurable outcomes such as attack success rate rather than subjective model quality.

## Testing

Run the test suite:

```bash
make test
```

Run tests with coverage:

```bash
make coverage
```

Run built-in self-tests:

```bash
make selftest
```

The project deliberately keeps the core implementation dependency-light so it can also be executed directly:

```bash
python redteam.py --selftest
```

## Design principles

### Local-first

The primary use case is testing models running on local infrastructure.

No cloud service is required when using Ollama or another local endpoint.

### Auditable

The implementation is intentionally compact.

There is no hidden agent framework, remote telemetry layer or mandatory external service.

### Reproducible

Runs capture attack definitions, model information, results and execution metadata.

### Comparable

The same attack manifest can be executed against different local models and the resulting metrics compared.

### Small by design

This project is not intended to replace larger red teaming frameworks.

It deliberately avoids becoming a general-purpose attack orchestration platform.

## Scope

This project focuses on prompt-level model behavior.

It does not currently attempt to provide:

* full semantic security evaluation
* model weight analysis
* automated exploit generation
* browser exploitation
* tool sandbox exploitation
* network penetration testing
* comprehensive OWASP coverage
* autonomous long-running attack agents

Those capabilities may be useful in larger systems, but they are outside the scope of this small reproducible harness.

## License

MIT
