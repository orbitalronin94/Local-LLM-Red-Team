# Research roadmap: expanding the red-team attack surface

This roadmap turns recent research into testable, resource-conscious extensions for Local LLM Red Team. It is a research backlog, not a claim that these capabilities are already implemented.

## Design principles
- Keep the default harness local-first and usable on CPU.
- Make every probe versioned, attributable to a paper or an explicit project hypothesis, and replayable.
- Separate model text behaviour from observable tool/state effects.
- Pair adversarial cases with benign controls; report utility and false-positive signals as well as attack outcomes.
- Do not treat heuristic detector outcomes as ground truth. Preserve raw responses for review.
- Add real tool execution only behind an explicit opt-in sandbox; simulated tool text must remain labelled as simulation.

## Priority 1 — Multi-turn and adaptive attacks
**Research basis:** [MAZE: One Refusal Isn’t Enough (EMNLP 2026)](https://aclanthology.org/2026.emnlp-main.2577/), [Adaptive Adversaries (arXiv:2607.18063)](https://arxiv.org/abs/2607.18063), and [AgentLAB (arXiv:2602.16901)](https://arxiv.org/abs/2602.16901).

Add scenario-driven conversations rather than isolated prompts: gradual context shaping and legitimacy construction; refusal recovery and reframing; objective drift; task injection and tool chaining; persistent-memory poisoning and later trigger attempts.

Use scenario files with stable scenario IDs, ordered turns, expected boundary, stop conditions and a bounded turn budget. Save complete transcripts and identify the first turn that crossed the boundary. Compare a single-turn baseline with the same final request after conversation history.

## Priority 2 — Tool, retrieval and MCP boundary testing
**Research basis:** [MCP Security Bench, ICLR 2026](https://openreview.net/pdf?id=irxxkFMrry), [SafeClawBench (arXiv:2606.18356)](https://arxiv.org/abs/2606.18356), and [Toward Secure LLM Agents (arXiv:2606.10749)](https://arxiv.org/abs/2606.10749).

Extend beyond simulated quoted text with an optional local mock-tool harness: hostile tool descriptions and name collisions; malicious tool results and false-error escalation; out-of-scope or privilege-escalating arguments; tool-transfer and confused-deputy scenarios; retrieval poisoning and provenance loss.

Keep tools deterministic and sandboxed. Start with fake tools that only read/write a temporary directory or in-memory state. No real email, shell, browser, network, cloud or production credentials. Record proposed calls separately from executed calls.

## Priority 3 — Separate semantic acceptance from actual impact
**Research basis:** [SafeClawBench](https://arxiv.org/abs/2606.18356) distinguishes semantic acceptance, audit evidence and sandbox-observed state/tool harm.

Introduce separate outcome fields: semantic acceptance; policy boundary crossed; tool call attempted; sandbox effect observed; audit evidence. This avoids conflating a model saying it will act with an action actually occurring. Keep ASR, benign utility, utility-under-attack, latency and execution errors distinct.

## Priority 4 — Spanish-first multilingual and code-switching suite
**Research basis:** [MMJail (WOAH 2026)](https://aclanthology.org/2026.woah-1.36/), [Does Safety Reasoning Travel? (ORACLE 2026)](https://aclanthology.org/2026.oracle-main.13/), [IndicSafeEval (Findings EMNLP 2026)](https://aclanthology.org/2026.findings-emnlp.2457/), and [Mātṛkā (2025)](https://aclanthology.org/2025.bhasha-1.10/).

Build matched English/Spanish families, not a handful of translated prompts: native Spanish phrasing and regional variants; cross-language transfer; code-switching within prompts and across turns; accents, punctuation, Unicode confusables and transliteration; persuasive framing and gradual multi-turn escalation.

Keep attack intent and difficulty matched, add benign hard negatives, and report per-language results. Translation artefacts can create false conclusions, so retain original and reviewed translations and record the review process.

## Priority 5 — Logical, structural and compositional attacks
**Research basis:** [Logic Jailbreak (Findings ACL 2026)](https://aclanthology.org/2026.findings-acl.25/), [JailbreakRadar (ACL 2025)](https://aclanthology.org/2025.acl-long.1045/), and [LAAF (arXiv:2603.17239)](https://arxiv.org/abs/2603.17239).

Add controlled families for formal/logical reframing and contradictory premises; nested delimiters, malformed structure and role-boundary confusion; encoding/normalization transformations; layered combinations of independently versioned techniques; trigger-conditioned payloads across conversation stages.

Do not generate an unbounded combinatorial corpus. Use deterministic, capped mutation plans with deduplication, seed IDs and recorded mutation lineage.

## Priority 6 — Lightweight adaptive attacker research
**Research basis:** [Adversarial Prompt Distillation (Findings AACL 2026)](https://aclanthology.org/2026.findings-aacl.75/) studies transferring attack-generation capability from larger models to smaller ones.

For this CPU-friendly project, first implement a deterministic mutation/search baseline (paraphrase templates, structural variants, language variants and response-conditioned selection). Later compare a small local attacker model. Measure generation cost, queries, time, diversity and incremental discoveries—not ASR alone. Keep attacker separate from target where possible; label self-play clearly.

## Evaluation protocol required for every new family
- Stable IDs, versions, source citation and a short threat-model statement.
- Matched benign controls and a single-turn baseline where applicable.
- At least two independently seeded runs for stochastic/adaptive cases; more for low-frequency outcomes.
- Preserve raw transcripts, target/model revision, quantization, inference settings, attack manifest hash and environment metadata.
- Report counts and uncertainty, not just percentages; avoid ranking models on tiny or unbalanced samples.
- Human review for ambiguous semantic outcomes. A judge model may assist but must not silently become ground truth.
- Regression tests for deterministic generation, serialization, replay and detector behaviour.

## Suggested implementation order
1. Scenario schema + multi-turn transcript/replay tests.
2. Spanish/English matched-pair expansion and benign controls.
3. Structured outcome schema and audit evidence.
4. Deterministic mutation engine with budgets and deduplication.
5. Optional mock-tool sandbox and MCP-shaped interface.
6. Adaptive attacker comparison and benchmark reports.

## Research references and limitations
These papers motivate candidate techniques; they do not prove that every reported attack transfers to small quantized local models. Reproduce only the parts that fit our threat model, pin paper/code/dataset versions, and measure the actual models in this repository. Some papers are very recent and their code/data may change. Check licences and dataset terms before importing prompts or corpora.
