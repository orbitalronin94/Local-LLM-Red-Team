# Authorized use and legal considerations

> **WARNING: Use this tool only against models, endpoints, accounts, data and infrastructure that you own or for which you have explicit, current authorization. Do not test systems belonging to others without permission.**

## Before running a test

1. **Obtain prior, documented authorization.** It must come from the owner or someone with sufficient authority. Define the authorized assets, models, endpoints, techniques, dates, load limits and points of contact in writing.
2. **Keep the scope narrow.** Configure the scanner to target only endpoints covered by the authorization. Do not expand testing to third-party networks, services, tools, accounts or data.
3. **Do not default to production testing.** Prefer isolated models and environments, synthetic data and local endpoints. Avoid destructive actions, denial of service, extraction of real data or persistent changes.
4. **Protect evidence.** Reports may contain prompts, responses, model names, endpoint addresses, sensitive data fragments or secrets disclosed by a model. Restrict access, encrypt storage where appropriate, redact secrets, and define retention and deletion periods.
5. **Stop if testing leaves scope**, produces unexpected effects, exposes unauthorized data or a stop request is received.

## Law: check every relevant jurisdiction

Legality depends on the country and sometimes the region, system type, data processed, contractual relationship and purpose of the test. Before using this tool, review the applicable law **in every country where the operator, system owner, infrastructure or affected data subjects are located**. Also check sector-specific rules, privacy and data-protection law, confidentiality, intellectual property, contracts, provider terms and internal policies.

This repository does not provide international legal certification or an exhaustive, continuously updated review of every country's laws. This notice is not legal advice, does not replace the system owner's authorization and does not guarantee that a particular test is lawful. If uncertain, consult qualified legal counsel in the relevant jurisdictions and the organization's security/privacy owner.

## Technical limits

Local LLM Red Team is a prompt-level behavior test harness. Heuristic findings do not by themselves prove access, exfiltration, tool execution or system modification. Do not connect it to real tools, production credentials or unnecessary personal data. PASS is not a security certification and NOT_DETECTED is inconclusive.

## Responsible-use terms

The operator is responsible for verifying authorization, scope, legal basis and applicable safeguards before running the tool. The authors and maintainers do not authorize unauthorized access or unlawful use. The software is provided "as is", under the project's license, without a warranty of fitness for a particular legal or security purpose.
