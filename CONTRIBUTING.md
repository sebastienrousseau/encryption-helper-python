# Contributing

Thanks for your interest in improving `encryption-helper-python`.

This project handles private key material, so a few of the conventions below
are stricter than you may be used to. Where that is the case, the reason is
given — none of them are ceremony.

## Reporting security issues

**Do not open a public issue for a security vulnerability.** Follow
[SECURITY.md](./SECURITY.md), which routes reports privately.

## Getting set up

Requires Python 3.10 or later and [Poetry](https://python-poetry.org/).

```bash
git clone https://github.com/hsbc/encryption-helper-python.git
cd encryption-helper-python

poetry install
poetry run pre-commit install
```

`pre-commit install` matters here: one of the hooks is `detect-private-key`,
which is the last thing standing between a stray test key and a public commit.

## The checks

Everything CI runs, you can run locally, with the same configuration:

```bash
poetry run pytest                                  # tests + 95% branch coverage gate
poetry run ruff check .                            # lint
poetry run ruff format --check .                   # formatting
poetry run mypy --strict encryption_helper         # types
poetry run bandit -c pyproject.toml -r encryption_helper
```

All configuration lives in `pyproject.toml`. There is deliberately no second
set of settings for CI to diverge from — an earlier version of this repository
had `.flake8` say 79 characters while CI passed `--max-line-length=127`.

## Conventions

### Commits

[Conventional Commits](https://www.conventionalcommits.org/):

```text
feat(keys): add Ed448 generation
fix(io): reject symlinked destinations
docs(readme): correct the private key container format
```

Use `!` or a `BREAKING CHANGE:` footer for anything that changes the public
API.

### Code

- Public functions need type annotations and a Google-style docstring with
  `Args`, `Returns` and `Raises`. `mypy --strict` must pass with no `type:
  ignore` that lacks an explanatory comment.
- Raise a typed error from `encryption_helper.errors`, never a bare
  `Exception`.
- **Error messages must never contain key material, passphrases or plaintext.**
  Assume every message reaches a log aggregator.
- Log lazily — `logger.info("read %s", path)`, not an f-string. The library
  configures no handlers; only `cli.py` may call `basicConfig`, and only
  `cli.py` may `print`.
- Anything that writes secret material goes through
  `encryption_helper._io.secure_write_bytes`, so the permission and overwrite
  rules stay in one place.

### Tests

This is where the project is most opinionated, because its predecessor shipped
a completely broken write path underneath a 97% coverage badge — the tests
mocked out the very function that was broken.

- **Do not mock the code under test.** Mocks are for injecting failures
  (`OSError` from a syscall), not for replacing the thing you are asserting on.
- Prefer real temporary files via `tmp_path` over a patched `open`.
- New behaviour needs a test that fails without the change.
- A bug fix needs a regression test that names the finding it closes.
- Security properties need a negative test: tampering must be *rejected*, not
  merely round-trip correctly.
- Coverage is measured with branch coverage and gated at 95%. Do not lower the
  gate to make a change fit.

## Pull requests

1. Branch from `main` (`feat/…`, `fix/…`, `docs/…`).
2. Make the change, with tests.
3. Ensure every check above passes.
4. Update `CHANGELOG.md` under `## [Unreleased]`.
5. Open the PR and fill in the template.

Expect review to focus on: whether the tests would actually fail if the code
were wrong, whether any error path can leak a secret, and whether a new
dependency is justified.

## Cryptographic changes

Changes to `encryption_helper/crypto/` get extra scrutiny:

- Use `cryptography`'s primitives. Do not implement a primitive, and do not
  reach into `_backend`.
- Changing the envelope container format requires bumping `VERSION` and
  keeping the old version readable.
- New constructions need test vectors cross-checked against an independent
  implementation (as the fingerprint tests do against `ssh-keygen`).
- Expect to be asked for external review before merge.

## Releasing

Maintainers only:

1. Update `CHANGELOG.md`, moving `Unreleased` to the new version.
2. Bump `version` in `pyproject.toml` — the only place a version is written.
3. Merge, then push a signed tag: `git tag -s v0.1.0 && git push --tags`.
4. The release workflow builds, attests provenance, and publishes to PyPI via
   Trusted Publishing. No token is handled by a human.
