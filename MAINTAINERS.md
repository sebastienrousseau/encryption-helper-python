<!-- SPDX-License-Identifier: Apache-2.0 -->

# Maintainers

| Name | Role | Contact |
| ---- | ---- | ------- |
| HSBC Open Source | Maintainer, security owner | <opensource@hsbc.com> |

Review requirements are enforced by [CODEOWNERS](./.github/CODEOWNERS):
cryptographic code, the I/O layer, the security policy, the workflows and the
lockfile all require a security owner.

## Becoming a maintainer

Sustained, high-quality contribution, plus familiarity with the invariants in
[ARCHITECTURE.md](./ARCHITECTURE.md). Open a discussion.

## Bus factor

One maintainer, stated plainly rather than hidden. If that matters for your
adoption decision, it should be weighed openly — the package is small, has one
runtime dependency, and is Apache-2.0, so forking is cheap.
