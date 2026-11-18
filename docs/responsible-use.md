# Responsible use and legal notice

Local LLM Red Team is a security-testing tool. It is provided for lawful research, education and assessments performed with explicit authorization.

## Authorization is mandatory

**Only test models, endpoints, systems and data that you own or are expressly authorized to assess. Do not use this tool against another person's or organization's systems without prior, explicit permission.** A system being reachable, publicly exposed, or technically testable does not imply permission.

Before every assessment:

1. Obtain written authorization from the system owner and identify the people or organization granting it.
2. Define the exact scope: hostnames, IPs, ports, API endpoints, models, accounts, test window, permitted techniques, request limits and prohibited actions.
3. Confirm that the authorization covers automated/adaptive testing and the specific prompts, payloads and traffic volume being used.
4. Use a dedicated test environment and synthetic data wherever possible. Do not submit real personal data, credentials, secrets or confidential third-party content.
5. Keep endpoints private, use least-privilege test credentials, set conservative limits and monitor the target.
6. Stop immediately if traffic reaches an out-of-scope system, causes unexpected effects, affects availability, or exposes data you are not authorized to access.
7. Retain evidence securely; redact secrets and personal data before sharing reports.

## Check the law in every relevant jurisdiction

The legal rules governing security testing differ by country and can also vary by state, province or region. They may depend on where the tester is located, where the system and its owner are located, where data subjects are located, and where the infrastructure is hosted.

**You are responsible for checking the laws and regulations applicable in every relevant jurisdiction before running a test.** This may include laws on unauthorized access or computer misuse, privacy and personal-data protection, confidentiality and communications interception, cybersecurity obligations, contracts, employment rules and sector-specific requirements. Also review the target provider's terms, internal policies and any third-party service agreements.

This repository does not provide legal advice, does not grant permission to test any system and does not certify that a particular use is lawful. If the scope or legal basis is unclear, do not run the test until you have obtained appropriate written authorization and qualified legal advice.

## Technical scope and limitations

The default project workflow is designed around local model inference. However, the CLI supports configurable HTTP and OpenAI-compatible endpoints; choosing a remote endpoint can send prompts and generated traffic to that service. Verify the destination and authorization before execution. Prompt-level findings do not establish that an external tool ran or that a real-world side effect occurred.

## No warranty

The software is provided "as is", without warranty. The user is responsible for configuration, test scope, operational safeguards, legal compliance and any consequences of use.
