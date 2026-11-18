# Local model assets and benchmark kit

Small GGUF models for repeatable local inference tests. Model weights are fetched on demand and are not committed to this repository.

| ID | Upstream model | GGUF quantization | Approx. size | License |
| --- | --- | --- | ---: | --- |
| smollm2 | [SmolLM2 360M Instruct](https://huggingface.co/QuantFactory/SmolLM2-360M-Instruct-GGUF) | Q4_K_M | 271 MB | Apache-2.0 |
| qwen2.5 | [Qwen2.5 0.5B Instruct](https://huggingface.co/tensorblock/Qwen2.5-0.5B-Instruct-GGUF) | Q4_K_M | 398 MB | Apache-2.0 |

The files are third-party GGUF quantizations. Their model cards identify the source model and license. SmolLM2's model card notes that the family primarily understands and generates English; use it as an additional stress target, not the only multilingual benchmark. Qwen2.5's model card describes multilingual support including Spanish.

## Download and integrity record

Run from the repository root:

```bash
python scripts/download_models.py --list
python scripts/download_models.py --model smollm2
python scripts/download_models.py --model qwen2.5
python scripts/download_models.py --model all
```

The downloader streams files to a temporary .part file, rejects suspiciously small or HTML responses, then atomically moves the completed file into models/weights/. It writes a sidecar .metadata.json containing the upstream repository, requested revision, response ETag, byte count, download timestamp and SHA-256. Use --force to replace an existing model. --dry-run prints URLs without network access.

The requested revision currently defaults to main; the sidecar ETag and SHA-256 record what was actually received. For strict long-term reproducibility, preserve the sidecar and pin an immutable upstream revision before a formal benchmark.

Weights are excluded from Git by the root .gitignore. Do not commit model weights or API credentials.

## Serve with llama.cpp

Install a current llama-server build separately. Example for SmolLM2:

```bash
llama-server --model models/weights/SmolLM2-360M-Instruct-Q4_K_M.gguf --host 127.0.0.1 --port 8080
```

Then run the existing OpenAI-compatible target:

```bash
mkdir -p reports
python redteam.py --target openai --url http://127.0.0.1:8080/v1 --model local-model --db reports/smollm2.db --json reports/smollm2.json --report reports/smollm2.md
```

Repeat with the Qwen2.5 GGUF and distinct report names. Keep scanner version, attack manifest, llama.cpp version, context size, sampling parameters, hardware and runtime flags constant. Record unavoidable differences. Compare individual attack IDs and response evidence, not only aggregate rates.

## Interpretation

These are compact smoke-test models, not a representative security benchmark and not a claim that a model family is safe or unsafe. The current detector is heuristic. PASS, FAIL and NOT_DETECTED are triage signals; inspect raw responses and use independent review for important conclusions.


## Automated full-catalog benchmark

The GitHub Actions workflow `.github/workflows/local-model-benchmark.yml` runs the complete built-in attack catalogue against both GGUF models. For each model it starts a CPU-only `llama-server`, generates a static report and an adaptive report (one attacker round), and uploads SQLite, JSON, Markdown, server logs and provenance as separate artifacts.

It can be started manually from **Actions → Local model red-team benchmark → Run workflow**. It also runs when the benchmark workflow, model downloader/catalogue or scanner changes on `main`. The benchmark uses public model files and does not require API secrets.

The adaptive run uses the tested model itself as the attacker. Treat this as a reproducible self-play stress test, not as an independent attacker evaluation. GitHub-hosted CPU performance and timeouts can vary; a failed model run is reported as failed, not as a clean security result.
