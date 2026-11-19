# Local model assets and benchmark kit

Small GGUF models for repeatable local inference tests. Model weights are fetched on demand and are not committed to this repository.

| ID | Model family / upstream | Parameters | GGUF quantization | Approx. size | License |
| --- | --- | ---: | --- | ---: | --- |
| smollm2 | [Hugging Face SmolLM2](https://huggingface.co/bartowski/SmolLM2-360M-Instruct-GGUF) | 360M | Q4_K_M | 271 MB | Apache-2.0 |
| qwen2_5 | [Alibaba Qwen2.5](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF) | 0.5B | Q4_K_M | 491 MB | Apache-2.0 |
| llama3_2_1b | [Meta Llama 3.2](https://huggingface.co/bartowski/Llama-3.2-1B-Instruct-GGUF) | 1B | Q4_K_M | 808 MB | Llama 3.2 Community License |
| gemma3_1b | [Google Gemma 3](https://huggingface.co/bartowski/google_gemma-3-1b-it-GGUF) | 1B | Q4_K_M | 806 MB | Gemma Terms |
| qwen2_5_3b | [Qwen2.5 3B](https://huggingface.co/bartowski/Qwen2.5-3B-Instruct-GGUF) | 3B | Q4_K_M | 1.93 GB | Apache-2.0 |
| llama3_2_3b | [Meta Llama 3.2 3B](https://huggingface.co/bartowski/Llama-3.2-3B-Instruct-GGUF) | 3B | Q4_K_M | 2.02 GB | Llama 3.2 Community License |
| gemma3_4b | [Google Gemma 3](https://huggingface.co/ggml-org/gemma-3-4b-it-GGUF) | 4B | Q4_K_M | 2.49 GB | Gemma Terms |

The GGUF files are community quantizations. Each catalogue entry records both the quantized repository and its upstream model. Licenses are not interchangeable: Llama and Gemma have their own terms; check the linked model card and upstream terms before redistribution or commercial use. SmolLM2 is primarily English-oriented, while Qwen2.5 is multilingual; do not interpret one language's result as a universal model score.

## Download and integrity record

Run from the repository root:

```bash
python scripts/download_models.py --list
python scripts/download_models.py --model smollm2
python scripts/download_models.py --model qwen2_5
python scripts/download_models.py --model llama3_2_1b
python scripts/download_models.py --model gemma3_1b
python scripts/download_models.py --model qwen2_5_3b
python scripts/download_models.py --model llama3_2_3b
python scripts/download_models.py --model gemma3_4b
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

The GitHub Actions workflow `.github/workflows/local-model-benchmark.yml` runs the complete built-in attack catalogue against seven GGUF models: SmolLM2 360M, Qwen2.5 0.5B and 3B, Llama 3.2 1B and 3B, and Gemma 3 1B and 4B. For each model it starts a CPU-only `llama-server`, generates a static report and an adaptive report (two-turn self-play), and uploads SQLite, JSON, Markdown, server logs and provenance as separate artifacts.

It can be started manually from **Actions → Local model red-team benchmark → Run workflow**. It also runs when the benchmark workflow, model downloader/catalogue or scanner changes on `main`. The benchmark uses public model files and does not require API secrets.

To populate the three larger-model caches before a benchmark, merge the model-catalogue change and manually run **Actions → Prepare local model cache** on `main`. That workflow downloads only Qwen2.5 3B, Llama 3.2 3B and Gemma 3 4B, records resolved revisions and SHA-256, and writes cache entries using the exact keys consumed by the benchmark. It does not start inference or run attacks. Model-catalogue/workflow-maintenance changes no longer auto-launch the expensive benchmark; dispatch it explicitly when ready.

The adaptive run uses the tested model itself as the attacker. Treat this as a reproducible self-play stress test, not as an independent attacker evaluation. Manual dispatch exposes `include_adaptive`: keep it enabled while completing the current cross-model comparison; turn it off to run the full static catalogue, scenarios, paired-language probes and robustness matrix without adaptive self-play. This is distinct from `benchmark_profile=quick`, which remains a reduced development screen. GitHub-hosted CPU performance and timeouts can vary; a failed model run is reported as failed, not as a clean security result.


## Persistent model cache

The benchmark workflow caches each GGUF independently with GitHub Actions cache, keyed by runner OS, model ID and the catalogue contents. The first run for a model downloads its weights; subsequent runs restore the cached file and sidecar metadata, then verify SHA-256 before starting inference. A catalogue change intentionally creates a fresh cache key. GitHub may evict old caches under its storage and retention policies, in which case that model is downloaded again. The cache stores benchmark assets, not reports or credentials.


## Focused benchmark set and next-run improvements

The active CI matrix now contains seven models spanning 360M–4B: SmolLM2 360M, Qwen2.5 0.5B/3B, Llama 3.2 1B/3B and Gemma 3 1B/4B. Granite, Phi and Ministral remain outside the routine matrix while their download/runtime failures are investigated; they are not classified as insecure or as failed security tests.

The workflow restores each model from its own GitHub Actions cache, validates sidecar provenance and recomputes SHA-256 before inference. The first run after a cache miss downloads the GGUF; later runs reuse it when GitHub retains the cache. This is persistent CI caching, not a guarantee that weights are permanently preinstalled on every ephemeral runner.

The next run records runner capacity, starts llama-server with one parallel slot, and sends a deterministic warm-up request before the attack suites. Future improvements: pin immutable GGUF revisions, add repeated seeded runs, separate target and attacker models, and expand matched Spanish-native probes with benign controls.
