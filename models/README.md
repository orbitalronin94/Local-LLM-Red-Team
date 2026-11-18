# Local model assets and benchmark kit

Small GGUF models for repeatable local inference tests. Model weights are fetched on demand and are not committed to this repository.

| ID | Model family / upstream | Parameters | GGUF quantization | Approx. size | License |
| --- | --- | ---: | --- | ---: | --- |
| smollm2 | [Hugging Face SmolLM2](https://huggingface.co/QuantFactory/SmolLM2-360M-Instruct-GGUF) | 360M | Q4_K_M | 271 MB | Apache-2.0 |
| qwen2_5 | [Alibaba Qwen2.5](https://huggingface.co/tensorblock/Qwen2.5-0.5B-Instruct-GGUF) | 0.5B | Q4_K_M | 398 MB | Apache-2.0 |
| llama3_2_1b | [Meta Llama 3.2](https://huggingface.co/bartowski/Llama-3.2-1B-Instruct-GGUF) | 1B | Q4_K_M | 808 MB | Llama 3.2 Community License |
| gemma3_1b | [Google Gemma 3](https://huggingface.co/bartowski/google_gemma-3-1b-it-GGUF) | 1B | Q4_K_M | 806 MB | Gemma Terms |
| granite3_3_2b | [IBM Granite 3.3](https://huggingface.co/bartowski/ibm-granite_granite-3.3-2b-instruct-GGUF) | 2B | Q4_K_M | 1.55 GB | Apache-2.0 |

The GGUF files are community quantizations. Each catalogue entry records both the quantized repository and its upstream model. Licenses are not interchangeable: Llama and Gemma have their own terms; check the linked model card and upstream terms before redistribution or commercial use. SmolLM2 is primarily English-oriented, while Qwen2.5 is multilingual; do not interpret one language's result as a universal model score.

## Download and integrity record

Run from the repository root:

```bash
python scripts/download_models.py --list
python scripts/download_models.py --model llama3_2_1b
python scripts/download_models.py --model gemma3_1b
python scripts/download_models.py --model granite3_3_2b
python scripts/download_models.py --model all
```

Install the downloader dependency with `python -m pip install -e ".[models]"`. The downloader uses `huggingface_hub.hf_hub_download` (rather than manually following Hugging Face file URLs), copies the cached file through a temporary .part file, verifies a minimum plausible size, then atomically moves it into models/weights/. It writes a sidecar .metadata.json containing the upstream repository, requested revision, byte count, download timestamp, backend and SHA-256. Use --force to replace an existing model. --dry-run prints the target repository/file without network access.

The requested revision currently defaults to main. For strict long-term reproducibility, preserve the sidecar and pin an immutable upstream revision before a formal benchmark.

Weights are excluded from Git by the root .gitignore. Do not commit model weights or API credentials.

## Serve with llama.cpp

Install a current llama-server build separately. Example:

```bash
llama-server --model models/weights/Llama-3.2-1B-Instruct-Q4_K_M.gguf --host 127.0.0.1 --port 8080
```

Then run the existing OpenAI-compatible target:

```bash
mkdir -p reports
python redteam.py --target openai --url http://127.0.0.1:8080/v1 --model local-model --db reports/llama-static.db --json reports/llama-static.json --report reports/llama-static.md
```

Keep scanner version, attack manifest, llama.cpp version, context size, sampling parameters, hardware and runtime flags constant. Compare individual attack IDs and response evidence, not only aggregate rates.

## Interpretation

These are compact smoke-test models, not a representative security benchmark and not a claim that a model family is safe or unsafe. The current detector is heuristic. PASS, FAIL and NOT_DETECTED are triage signals; inspect raw responses and use independent review for important conclusions.

## Automated full-catalog benchmark

The GitHub Actions workflow `.github/workflows/local-model-benchmark.yml` runs the complete built-in attack catalogue against all five GGUF models. For each model it starts a CPU-only `llama-server`, generates a static report and an adaptive report (one attacker round), and uploads SQLite, JSON, Markdown, server logs and provenance as separate artifacts.

It can be started manually from **Actions → Local model red-team benchmark → Run workflow**. It also runs when the benchmark workflow, model downloader/catalogue or scanner changes on `main`. The benchmark uses public model files and does not require API secrets.

The adaptive run uses the tested model itself as the attacker. Treat this as a reproducible self-play stress test, not as an independent attacker evaluation. GitHub-hosted CPU performance and timeouts can vary; a failed model run is reported as failed, not as a clean security result.
