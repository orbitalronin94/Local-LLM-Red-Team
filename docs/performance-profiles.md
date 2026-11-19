# Performance profiles and generation budgets

## Purpose

Reduce the time spent on development feedback loops without changing the meaning or scope of the official benchmark. The quick profile is a screening aid, not a substitute for the full evaluation.

## Profiles

| Profile | Static catalogue | Adaptive self-play | Multi-turn scenarios | Paired EN/ES suite | Seed/paraphrase matrix |
| --- | --- | --- | --- | --- | --- |
| quick | Fixed 8-attack subset | Skipped | Skipped | Skipped | Skipped |
| full | All catalogue attacks | Full configured run | All scenarios | All matched pairs and controls | All configured seeds and variants |

The quick subset spans jailbreak, instruction override, system extraction, prompt injection and persistence, and includes English and Spanish prompts. Its exact IDs are maintained in QUICK_PROFILE_ATTACK_IDS; its selected attack manifest is written into the normal run metadata.

Use local-llm-redteam --profile quick locally. Quick mode is static-only and cannot be combined with explicit --attack or --category filters. The CLI rejects those combinations rather than silently changing the requested cohort.

The GitHub Actions workflow exposes benchmark_profile on manual dispatch. The default is full. Push-triggered benchmark runs always remain full, so normal CI and official benchmark artifacts do not silently lose coverage.

## Generation budget

All target adapters accept the optional --max-output-tokens N setting. It maps to OpenAI-compatible max_tokens and Ollama options.num_predict. When omitted, no cap is added and the target/server default is preserved.

Quick workflow runs use 192 generated tokens per response. This cap is deliberately not applied to full runs. A cap can truncate a response; the adapters preserve the finish reason, and the scanner marks length-truncated evidence for review. A truncated answer must not be interpreted as a clean refusal or a completed probe. The paired-language and scenario reports preserve finish-reason provenance and mark truncated outputs for human review. The controlled persistence protocol aborts an incomplete oracle phase and labels the run `incomplete_truncated_response`; robustness summaries count it separately from transport errors and exclude it from the valid attack cohort.

The configured cap is included in target provenance and in the static scan run metadata. For other command-line suites, the per-turn provenance records the configured cap. A null cap means the server default was used.

## Interpreting comparisons

- Compare quick runs only with the same quick profile, attack manifest, model revision, server build and generation cap.
- Do not pool quick and full denominators or compare their raw rates as if they had equal coverage.
- A quick-profile NOT_DETECTED result is inconclusive; omitted suites are NOT TESTED, not passed.
- Use the full profile for release decisions, cross-model claims and published benchmark results.
- Use targeted --attack / --category selections for local debugging when one detector or mitigation is under development; record the selection because it changes the evaluated cohort.

The goal is fewer redundant inference calls per development iteration, not weaker evidence in the official evaluation.
