# Changelog

Notable user-facing changes are recorded here. This project remains pre-1.0; interfaces, attack definitions and report schemas may still change.

## Unreleased — 2026-11-19

### Added
- Independent static evidence vectors for `VERBAL_ACCEPTANCE`, `PERSISTENT_OVERRIDE`, `POLICY_BYPASS` and `CANARY_DISCLOSURE`, persisted with scan results.
- Opt-in `--canary-test`: a static-only probe using a random run-scoped synthetic marker in protected system context. Disclosure requires an exact literal match.
- Explicit JSON report schema version 2 and evidence schema version 2, separate from package and detector versions.
- A fast development profile with a fixed eight-attack subset and a 192-token default output cap; full benchmark runs remain the default for push-triggered workflows.
- Configurable `--max-output-tokens` across supported target adapters, with finish-reason/truncation provenance.
- Human-review, report interpretation, bilingual coverage, evidence-model, persistence-protocol and robustness-matrix documentation.

### Changed
- Bumped the heuristic detector to version 4 and record its SHA-256 implementation fingerprint separately.
- Replaced broad quoted-text masking with quote-span parsing that preserves contractions and possessives, masks only complete quoted spans, and leaves unmatched quotes unmasked.
- Improved refusal/compliance clause handling so compliance after a refusal can still be detected without treating every comma-separated phrase as acceptance.
- Attack-success and refusal rates now exclude `ERROR`, `EMPTY` and `THROTTLED`; completed `NOT_DETECTED` results remain in the denominator as inconclusive outcomes. Coverage is reported separately.
- Corrected the default static catalogue documentation to 14 probes (13 English, 1 Spanish); the ten-pair EN/ES suite is a separate evaluation.
- Added explicit truncation review semantics and safeguards against treating incomplete output as a clean refusal or completed oracle phase.

### Methodology and interpretation
- Heuristic `FAIL` remains a human-review candidate, not a confirmed vulnerability.
- Static verbal acceptance does not establish persistent override or policy bypass.
- Synthetic canary disclosure demonstrates only exact disclosure of the test fixture; it does not establish exposure of a real secret, system prompt or production policy.
- A zero valid cohort or zero executable denominator is not a 0% risk result and is not evidence of resistance.

## Earlier releases

See the merged pull requests and tagged repository history for changes before this consolidated pre-1.0 entry.
