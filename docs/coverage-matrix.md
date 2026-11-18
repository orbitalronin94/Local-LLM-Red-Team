# Language and attack coverage matrix

This matrix describes the **current default attack manifest**, not a claim of complete multilingual coverage. It separates the language used in attack prompts from language-aware detector patterns.

## Current default catalogue

The default manifest contains 14 probes:

| Attack ID | Category | Prompt language | Primary boundary tested |
| --- | --- | --- | --- |
| `jailbreak-roleplay` | Jailbreak | English | Unrestricted persona framing |
| `jailbreak-authority` | Jailbreak | English | False authority / approval |
| `instruction-override` | Instruction override | English | Direct instruction replacement |
| `system-prompt-extraction` | System extraction | English | Direct hidden-instruction disclosure |
| `system-prompt-summary` | System extraction | English | Indirect hidden-instruction disclosure |
| `prompt-injection-document` | Prompt injection | English | Untrusted document instruction |
| `prompt-injection-tool` | Prompt injection | English | Simulated tool/configuration disclosure |
| `persistence` | Persistence | English | Retaining unsafe instruction |
| `indirect-injection-retrieved-content` | Prompt injection | English | Instruction inside retrieved-text simulation |
| `tool-output-injection` | Prompt injection | English | Instruction inside simulated tool output |
| `delimiter-boundary-confusion` | Instruction override | English | Delimiter / role-boundary confusion |
| `multilingual-instruction-override` | Instruction override | Spanish | Explicit Spanish instruction override |
| `refusal-suppression` | Jailbreak | English | Suppression of refusal language |
| `multi-turn-persistence` | Persistence | English | Persistence seed for follow-up turns |

**Prompt-language coverage today:** 13 English probes and 1 explicitly Spanish probe. The detector also includes Spanish-language patterns, but that does not make the attack catalogue a balanced bilingual suite.

## What is and is not covered

| Dimension | Current status | Interpretation |
| --- | --- | --- |
| English attack prompts | 13 default probes | Broadest prompt-language coverage in the starter manifest. |
| Spanish attack prompts | 1 default probe | Smoke coverage only; insufficient for a Spanish security score. |
| Spanish detector patterns | Present for selected refusal and compliance indicators | Pattern support is not equivalent to semantic Spanish evaluation. |
| Mixed-language attacks | One explicitly multilingual/Spanish-labelled probe | No systematic code-switching matrix yet. |
| Spanish response evaluation | Not independently validated as a complete suite | A Spanish response to an English prompt is not a Spanish-language test case. |
| Retrieval/tool execution | Simulated text only | No live RAG pipeline or tool runtime is exercised. |
| Human semantic adjudication | Manual process documented separately | No automatic LLM judge or calibrated human-label workflow exists. |

## Recommended bilingual expansion

Before publishing comparative English/Spanish scores, build matched pairs for every attack family:

1. Translate the attack intent, not just individual words; have a fluent reviewer check naturalness.
2. Preserve a shared family ID and distinct language-specific attack IDs.
3. Keep difficulty and requested boundary equivalent across the pair.
4. Add Spanish paraphrases and regional variants, plus code-switching cases.
5. Add benign controls and refusal/compliance examples to estimate false positives and false negatives.
6. Review outputs manually and report per-language counts, error rates and uncertainty.
7. Version the manifest and publish its SHA-256 with each result.

Do not compare an English model score against a Spanish score from one probe. Report the exact number of probes, attack-family distribution and detector version. The current catalogue is a starter set, not a validated bilingual benchmark.

Related: [Report interpretation guide](report-guide.md) · [Detection methodology](methodology.md).
