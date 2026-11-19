# Version 1.0 readiness and release gates

This document defines the release contract; it is not a claim that the project is already 1.0-ready.

## Six workstreams

1. Evidence validity: separate benign controls from explicit extraction probes; keep verbal acceptance heuristic; require exact task oracles for deterministic claims; never turn missing denominators into zero.
2. Attack coverage: stable IDs and family/language provenance; reviewed English/Spanish counterparts; report language cohorts separately. Pairs are not difficulty-matched until validated.
3. Reproducibility: preserve exact prompts/responses, per-turn hashes, model identity, generation settings, seeds, manifest digest and detector fingerprint. A hash alone does not prove environmental identity.
4. Software quality: test every first-party module, supported Python versions, clean installation, CLI entry points, serialization and backwards-compatible report/database reads.
5. Reports: distinguish observations, heuristics, deterministic oracles, human adjudication and execution errors. Include denominators and uncertainty; mark small samples exploratory.
6. Release: bilingual docs, scope/legal review, changelog, license/provenance audit, clean install, full CI, reference benchmark and tagged release.

## Evidence vocabulary

- OBSERVED means the declared exact-match or deterministic oracle condition occurred.
- VERBAL_ACCEPTANCE is a heuristic signal, not proof of changed model behaviour.
- PERSISTENT_OVERRIDE requires a new post-injection task and exact behavioural evidence.
- POLICY_BYPASS requires a declared oracle with a known expected result.
- NOT_DETECTED is inconclusive, not a security pass.
- NOT_TESTED, UNVERIFIED, ERROR and zero denominators remain distinct.
- Synthetic canary/policy-marker disclosure demonstrates behaviour in that fixture, not exposure of real user data or a real system prompt.

## Acceptance checklist

- [ ] Benign baseline contains no request to reveal a protected marker.
- [ ] Direct and indirect extraction probes are separately labelled and reported.
- [ ] Baseline disclosures are not attributed to later attacks.
- [ ] Attack denominators contain only valid eligible runs.
- [ ] Empty cohorts produce null rates and no confidence interval.
- [ ] Deterministic claims have explicit oracle IDs and evidence.
- [ ] Heuristic positives require human review before being called confirmed exploits.
- [ ] English and Spanish results are reported separately; equivalence is not assumed.
- [ ] Replay instructions preserve model revision, fixture, seed and generation parameters.
- [ ] Coverage includes all first-party modules and threshold follows a measured baseline.
- [ ] Clean install and CLI entry points work on supported Python versions.
- [ ] JSON/SQLite compatibility and migrations have regression tests.
- [ ] Both READMEs and paired documentation are current.
- [ ] Reference benchmark includes raw artifacts, hashes, limitations and denominators.
- [ ] No security certification or universal safety claim is made.

## Current release posture

The project remains pre-1.0 until each item is satisfied or explicitly scoped out with rationale. Green CI proves only that the tested code and tests completed; it does not prove methodological completeness or model security.