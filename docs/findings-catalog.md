# Automated findings catalogue

Each benchmark run generates a `redteam-findings-catalog` artifact containing:

- `findings-catalog.md`: prompts, responses, model identity, revision, hash, category, run and detector evidence.
- `findings-catalog.json`: structured records.
- `findings-catalog.csv`: spreadsheet-friendly index.

## Inclusion rules

`FAIL` results are listed as **heuristic positives**. `NOT_DETECTED` results requiring review are listed separately as **inconclusive cases**. They are not presented as successful attacks or evidence of safety. Multi-turn scenarios retain their turns; EN/ES probes retain language and original prompt.

Per-model reports remain the primary evidence. The catalogue is regenerated per run and does not overwrite earlier runs.

## Local generation

After extracting the per-model artifacts into a common directory:

    python scripts/build_findings_catalog.py --input-dir reports --output-dir reports/catalog --run-label 44339206162

## Limitations

- `FAIL` means the heuristic detector matched a signal; it does not prove exploitation, secret extraction, tool execution or production impact.
- `NOT_DETECTED` is inconclusive and is not equivalent to `PASS`.
- No case is human-confirmed until an explicit human review is recorded.
- Missing immutable model revisions or hashes remain unresolved/not recorded.
