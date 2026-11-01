# Security Policy

Olivares AI is a security product that runs on customer hosts and maps what each agent can access. A flaw in it can become a flaw in the systems it observes, so we hold the bar high by design and we want to hear about problems quickly. Thank you for helping keep it safe.

## Reporting a vulnerability

Report security issues privately to **security@olivares.ai**. Please do **not** open a public issue, pull request, or discussion for a suspected vulnerability.

Include where you can:

- A clear description of the issue and its impact.
- Affected component(s) and version / commit (`olivares version`).
- Steps to reproduce, a minimal proof of concept, and relevant configuration.
- Any suggested remediation.

If you wish to encrypt your report, request our PGP key at the same address before sending details.

This contact is also published machine-readably as an [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) `security.txt`, served at `https://olivares.ai/.well-known/security.txt`. No PGP key is published yet, so that file advertises no `Encryption` field — request the key as above.

## Coordinated disclosure

We follow coordinated disclosure and operate under a good-faith safe harbor: to the extent permitted by applicable law, we will not pursue or support legal action against researchers who act in good faith, stay within the scope below, and give us a reasonable chance to fix the issue before going public. This safe harbor is a unilateral statement by Olivares AI about its own conduct: it binds no one else — not a customer whose deployment you probe, not a hosting or cloud provider, and not a public authority — and it authorises nothing against systems you do not own or lack permission to test.

- **Acknowledgement:** within 3 business days.
- **Initial assessment / triage:** within 10 business days.
- **Coordinated disclosure window:** up to 90 days from acknowledgement, shortened when a fix ships earlier or extended by mutual agreement for complex issues.

These timeframes are **targets of a single-maintainer project, not contractual commitments**: they are not an SLA, they create no right or remedy for anyone, and missing one is not a breach of any agreement.

We will keep you updated through triage and fix, and we are glad to credit reporters in the release notes unless you prefer to remain anonymous.

## Scope

This repository is the Community recipe of the Olivares Server appliance: first boot, the image recipe, the SELinux
module and the Appliance Console. The product itself, its supported versions and its security advisories are covered by
the SECURITY.md of the Olivares AI repository (https://github.com/olivaresai/olivares).

## What not to include in a report

To avoid making the situation worse, do **not** include in your report:

- Real secrets, credentials, API keys, or tokens — redact them.
- Customer or third-party personal data (PII), or production data dumps.
- Live exploitation against systems or data you do not own or lack permission to test.

If demonstrating impact requires sensitive data, describe it rather than attaching it, and we will arrange a secure channel.
