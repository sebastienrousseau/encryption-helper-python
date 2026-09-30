# Security Policy

`encryption-helper-python` generates and handles private key material. Security
issues in this project can directly compromise its users' secrets, so we treat
them with priority.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.0.2   | :white_check_mark: |
| 0.0.1   | :x: |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues,
discussions, or pull requests.**

Report privately through either channel:

1. **GitHub Security Advisories** (preferred) — use
   [Report a vulnerability](https://github.com/hsbc/encryption-helper-python/security/advisories/new)
   on this repository. This keeps the report private until a fix is published.
2. **Email** — <opensource@hsbc.com>, with `encryption-helper-python` in the
   subject line.

Please include, as far as you are able:

- The affected version or commit.
- A description of the issue and its impact.
- Steps to reproduce, ideally a minimal proof of concept.
- Any suggested mitigation.

Do not include real private keys, passphrases, or other live secrets in your
report. Redact them or substitute freshly generated test material.

## What to expect

| Stage | Target |
| ----- | ------ |
| Acknowledgement of your report | Within 2 business days |
| Initial assessment and severity triage | Within 5 business days |
| Status update cadence while we work | At least every 7 days |
| Fix released, or a documented mitigation and timeline | Within 90 days of triage |

If a report is accepted, we will credit you in the advisory and the changelog
unless you ask us not to. If a report is declined, we will explain why.

We follow coordinated disclosure: we ask that you give us the 90-day window
before disclosing publicly, and we will work with you if a fix legitimately
needs longer.

## Scope

In scope:

- Key material being exposed, weakened, logged, or written with unsafe
  permissions.
- Flaws in cryptographic construction, parameter choice, or use of the
  underlying `cryptography` primitives.
- Path traversal, symlink attacks, or unsafe file handling in key input/output.
- Supply-chain issues in our build, release, or CI configuration.

Out of scope:

- Vulnerabilities in the upstream [`cryptography`](https://github.com/pyca/cryptography)
  library — report those to that project. Tell us anyway if this project's use
  of it makes the impact worse.
- Attacks requiring an already-compromised host or an attacker who already has
  read access to the private key file.
- Missing hardening that does not lead to a concrete exploit, though we welcome
  these as normal issues.
