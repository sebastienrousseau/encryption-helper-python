## What does this change?

<!-- A short description, and the issue it closes. -->

Closes #

## Why?

<!-- The problem being solved. -->

## Checklist

- [ ] Tests added or updated, and they fail without this change.
- [ ] No test mocks the code it is asserting on.
- [ ] `poetry run pytest` passes, including the 95% branch-coverage gate.
- [ ] `poetry run ruff check . && poetry run ruff format --check .` passes.
- [ ] `poetry run mypy --strict encryption_helper` passes.
- [ ] `CHANGELOG.md` updated under `## [Unreleased]`.
- [ ] Public functions have type annotations and Google-style docstrings.

## Security

- [ ] No new error message, log line, or console output can contain key
      material, a passphrase, or plaintext.
- [ ] Anything writing secret material goes through `secure_write_bytes`.
- [ ] This PR does **not** change `encryption_helper/crypto/`.
      <!-- If it does, describe the construction and how it was validated. -->

## Breaking changes

<!-- Describe any, with a migration note for CHANGELOG.md. Otherwise "None". -->
