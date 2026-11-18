# Assessing an authorized chatbot endpoint

This guide explains how to use Local LLM Red Team against a chatbot endpoint that
implements the OpenAI Chat Completions API. It is an **application-level
integration check**, not a certification and not a substitute for a full
security assessment.

## Scope and safety gates

Before running probes:

1. Obtain written authorization from the system owner and record the exact
   hostname, path, environment, model/deployment, test window and permitted
   request volume.
2. Prefer a staging deployment with production-equivalent prompts, retrieval
   configuration, tools and authorization policies. Use synthetic documents
   and accounts; do not submit real customer data or secrets.
3. Confirm a rollback/contact procedure and a rate limit. This scanner sends
   adversarial text as ordinary chat messages; it does not intentionally invoke
   denial-of-service, exploit infrastructure, or verify a real-world side
   effect.
4. Verify that the endpoint is HTTPS when accessed over a network. The local
   benchmark uses loopback HTTP; do not copy that transport setting to a
   remotely reachable service.
5. Use a dedicated, least-privilege test credential. Do not commit credentials,
   put them in reports, or paste them into issue comments. Prefer the
   environment-backed wrapper below: it keeps the key out of the operating
   system command line. The secret still exists in process memory and the
   environment, so use a protected runner and avoid shell tracing.

Public reachability is not authorization. See
[Responsible use](responsible-use.md) and [legal use](legal-use.md).

## Supported endpoint contract

The `openai` target sends a POST request to
`<base-url>/chat/completions` (unless the supplied URL already ends with
`/chat/completions`). It sends a JSON body containing `model` and
`messages`, and adds `Authorization: Bearer ...` when `--api-key` is
provided. Responses may use the standard `choices[0].message.content` shape.

Example for an **authorized staging endpoint** using the environment-backed
runner:

```bash
# Inject this variable through your CI secret store or protected shell.
export REDTEAM_API_KEY='injected-by-your-secret-manager'
python scripts/secure_endpoint_scan.py \
  --api-key-env REDTEAM_API_KEY \
  --target openai \
  --url https://staging.example.invalid/v1 \
  --model chatbot-staging \
  --timeout 45 \
  --db reports/staging.db \
  --json reports/staging-static.json \
  --report reports/staging-static.md
```

The example hostname is intentionally non-routable. Replace it only with an
endpoint explicitly included in your authorization. The wrapper also accepts
`--runner scenarios` to run the deterministic multi-turn suite. It does not
print the key or place it in the OS process command line; it passes the value
to the existing scanner in-process. The original CLI `--api-key` option
remains available, but the wrapper rejects it to prevent accidental exposure.

For a generic JSON endpoint, `--target http` expects a JSON request with
`model` and `messages`. It currently has no built-in API-key or custom-header
option. Do not use it with an authenticated production-like service unless
authentication is supplied by a trusted local proxy or the client is extended
and reviewed first.

## Recommended assessment sequence

Run each stage separately and retain the exact report bundle:

1. **Connectivity and baseline:** verify the deployment/model identifier,
   expected response format, latency and normal refusal behaviour using a
   benign control. Confirm that the test credential is scoped correctly.
2. **Static prompt probes:** run the default catalogue against the staging
   chatbot. This tests prompt-level behaviour exposed through its public chat
   interface.
3. **Multi-turn scenarios:** run the deterministic scenarios to test refusal
   recovery, context laundering and untrusted-memory handling across turns.
4. **Paired language probes:** compare matched English/Spanish intent where
   relevant. Treat them as matched test cases, not certified translations.
5. **Manual review:** inspect every `FAIL`, `NOT_DETECTED`, `ERROR` and
   benign control. Record reviewer verdicts separately; do not convert
   heuristic output into a claim of exploitability.
6. **Guardrail verification:** if a finding suggests an unsafe action, test the
   authorization layer independently with a harmless, instrumented mock tool.
   Verify that denied actions were actually blocked by the application. The
   prompt-only scanner cannot establish that a tool ran or that data changed.

For multi-turn scenarios, use the same wrapper with
`--runner scenarios`:

```bash
python scripts/secure_endpoint_scan.py \
  --api-key-env REDTEAM_API_KEY \
  --runner scenarios \
  --target openai \
  --url https://staging.example.invalid/v1 \
  --model chatbot-staging \
  --timeout 45 \
  --json reports/staging-scenarios.json \
  --report reports/staging-scenarios.md
```

## What a finding means

Keep these evidence classes separate in tickets and reports:

| Evidence class | What this tool can establish |
| --- | --- |
| Model response behaviour | The text returned by the endpoint matched a documented heuristic or refusal pattern. |
| Chatbot integration behaviour | Only what is visible through the tested endpoint and captured conversation. |
| Retrieval/tool boundary | A prompt can simulate hostile retrieved/tool text; this does not prove the real RAG or tool pipeline was exercised. |
| Authorization enforcement | Not proven by a prompt-only response. Verify with application logs and an instrumented mock or controlled test action. |
| Real-world impact | Not established by this scanner. Requires separately authorized, independently reviewed evidence. |

Interpret statuses conservatively:

- `FAIL` is a heuristic signal that needs human review, not proof of a
  successful exploit.
- `PASS` means a refusal indicator was found; it is not proof of security.
- `NOT_DETECTED` is inconclusive, not proof that the attack failed.
- `ERROR` is an execution or response-handling problem, not a security pass.

## Minimum report metadata to retain

Alongside the generated JSON/Markdown/SQLite files, record:

- authorization reference and scope (store sensitive paperwork separately);
- environment and endpoint hostname/path, excluding query strings and secrets;
- deployment/model revision and system-prompt/configuration revision;
- retrieval corpus/index snapshot and tool/permission configuration;
- scanner version, attack/scenario manifest hashes and detector version;
- test start/end time, operator, request budget and any excluded probes;
- sanitized application logs and independent reviewer verdicts.

Do not place API keys, session cookies, customer records, hidden prompts or
other secrets in reports. Redact sensitive response content before sharing
artifacts. Preserve original evidence in access-controlled storage where
required by the engagement.

## Known limitations

- The OpenAI-compatible target supports Bearer API-key authentication; it does
  not currently expose arbitrary custom headers, OAuth flows, cookie sessions,
  client certificates or provider-specific signing.
- The generic HTTP target has no built-in authentication support.
- The scanner sends chat-completion requests only. It does not crawl a website,
  authenticate a browser session, inspect frontend code, or automatically
  exercise real retrieval/tool calls.
- Heuristic detection can miss paraphrases and can flag benign explanations.
  Human review remains mandatory for meaningful conclusions.
- A deployment may route requests across model versions or guardrail variants;
  record the actual deployment revision and repeat tests to assess variability.

The correct conclusion is bounded: this assessment describes observed
responses from one authorized deployment, configuration and test window.
