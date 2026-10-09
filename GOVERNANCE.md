<!-- SPDX-License-Identifier: Apache-2.0 -->

# Governance

## Ownership

Maintained by HSBC Open Source. See [MAINTAINERS.md](./MAINTAINERS.md) for the
current list and [CODEOWNERS](./.github/CODEOWNERS) for review requirements.

## Decisions

Routine changes — bug fixes, documentation, dependency updates — need one
maintainer approval.

Changes to `encryption_helper/crypto/` or `encryption_helper/_io.py` need
review from a security owner, per `CODEOWNERS`. New cryptographic
constructions additionally need external review before release; see the
rationale in [CONTRIBUTING.md](./CONTRIBUTING.md).

Changes to the container format, the exception hierarchy or exit codes are
breaking and need explicit sign-off plus a `CHANGELOG` migration note.

## Adding an algorithm

Allocate a new identifier; never change an existing one. An old ciphertext or
signature must stay verifiable. Anything else is a format break.

## Deprecation

Algorithms are not removed when a standards body deprecates them — that would
strand existing material. They are marked in `capabilities`, surfaced as a
notice at generation time, and documented with their horizon. Removal needs a
major version.

## Security reports

Private, per [SECURITY.md](./SECURITY.md). A vulnerability report takes
precedence over feature work.
