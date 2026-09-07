# Encryption Helper Python — Deep-Dive Analysis & Implementation Plan

**Target:** 10/10 across all categories
**Branch:** `feat/v0.0.2`
**Analysis date:** 2026-09-07
**Baseline commit:** `6bfd51d`
**Analysed by:** static review + empirical verification (tests, linters, runtime probes) on Python 3.14.7 / cryptography 50.0.1

---

## 0. Executive summary

`encryption-helper-python` is a ~420-LOC package published by HSBC that generates a single
2048-bit RSA key pair and writes it to `keys/pem/`. It is well-docstringed and superficially
clean — 34 tests pass, pylint reports 10.00/10, bandit reports zero issues, flake8 is nearly
clean.

Those green signals are misleading. Empirical verification found:

- The repository **ships an Apache-2.0 LICENSE file while declaring MIT** in four places.
- The tool **writes private keys world-readable (0644) and prints them to stdout**.
- One of its two utility modules (`write_file`) is **unconditionally broken** — every
  documented call raises — and the test suite cannot detect it because it mocks out the
  faulty function.
- `pylint` scores 10/10 only because `.pylintrc` begins with `disable=all`. Under the default
  ruleset the score is 9.34/10, and the rcfile itself contains a syntax error and 19 stale
  or invalid directives.
- `bandit` is configured but **never runs in CI**.
- Source code has not been modified since **2024-07-27**; all 80+ commits since are Renovate
  dependency bumps.

### Current rating

| # | Category | Score | One-line justification |
|---|----------|-------|------------------------|
| 1 | Correctness & functionality | **3/10** | A core utility module fails 100% of documented calls (C5) |
| 2 | Security | **2/10** | Private key at 0644, echoed to stdout, unencrypted, silently overwritable |
| 3 | Architecture & API design | **4/10** | Dead code, no CLI surface, global-state singleton, library prints |
| 4 | Testing | **3/10** | 97% line coverage that provably detects nothing; zero integration tests |
| 5 | Packaging & distribution | **4/10** | Dual/conflicting setup.py + Poetry, version in 3 places, never released |
| 6 | CI/CD & automation | **4/10** | Unhardened workflows, bandit unused, no coverage gate, no CodeQL |
| 7 | Documentation | **5/10** | Good docstrings; README factually wrong on PKCS standard, no badges/API ref |
| 8 | Licensing & governance | **2/10** | License contradiction; SECURITY.md is an unedited template |
| 9 | Type safety & code quality | **4/10** | Half the package unannotated, no `py.typed`, no mypy, self-neutered linters |
| 10 | Release & maintenance | **2/10** | No tags, no releases, not on PyPI, source dormant 2+ years |
|   | **Overall** | **≈3.3/10** | |

### Scope note on versioning

The work below removes `Context`, changes the `generate_rsa_key()` signature and return
contract, and stops printing keys. These are **breaking changes**. Under semver this warrants
**`0.1.0`**, not `0.0.2`. Recommendation: retarget the branch or accept that `0.0.x` carries no
compatibility promise and document that explicitly.

---

## 1. Findings

Severity: **C**ritical (ship-blocking / legal / key-compromising) · **H**igh · **M**edium · **L**ow.
Every finding marked *[verified]* was reproduced at runtime, not merely read.

### 1.1 Critical

---

#### C1 — LICENSE file (Apache-2.0) contradicts every license declaration (MIT) *[verified]*

`LICENSE` lines 1–3 read `Apache License / Version 2.0, January 2004` (169 non-blank lines,
consistent with Apache-2.0; MIT is ~20 lines). But:

| Location | Declares |
|---|---|
| `pyproject.toml:6` | `license = "MIT"` |
| `pyproject.toml:12` | `"License :: OSI Approved :: MIT License"` |
| `setup.py:23` | `license="MIT"` |
| `setup.py:25` | `"License :: OSI Approved :: MIT License"` |
| `README.md` (License section) | "licensed under the MIT License" |

**Impact.** Downstream consumers cannot determine the governing terms. The two licenses are not
interchangeable: Apache-2.0 carries an express patent grant, a NOTICE-file obligation, and
attribution requirements that MIT does not. For a bank-published repository this is a legal
defect, not a typo. GitHub's license detector and PyPI metadata will disagree with the file.

**Action.** Escalate to HSBC Open Source / legal to determine intent. Do **not** silently pick
one. Once decided, make all five locations agree and add `NOTICE` if Apache-2.0 is chosen.

---

#### C2 — Private key written world-readable (0644) *[verified]*

`encryption_helper/main.py:68-69`:
```python
with open(keys_dir / "private-key.pem", "wb") as file_out:
    file_out.write(private_key)
```

Observed after a real run:
```
-rw-r--r--  1 rousseau rousseau  1704  private-key.pem
-rw-r--r--  1 rousseau rousseau   451  public-key.pem
```

**Impact.** On any multi-user or shared-CI host, every local account can read the generated
private key. `open()` honours the process umask (typically 022); it never restricts.

**Action.** Create the file with explicit restrictive mode *before* writing:
```python
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
```
Also `keys_dir.mkdir(..., mode=0o700)`. On Windows, fall back to an ACL narrowed to the current
user (`icacls` / `pywin32`) and document the platform difference.

---

#### C3 — Private key printed to stdout and emitted to the DEBUG log *[verified]*

`main.py:77` `logger.debug(f"Private key:\n{private_key.decode()}\n")`
`main.py:82-83` `print("\nPrivate key:"); print(private_key.decode())`

A real run emits `-----BEGIN PRIVATE KEY-----` to stdout (confirmed by grep of captured output).

**Impact.** The secret lands in terminal scrollback, `script`/`tee` captures, CI job logs (public
on GitHub Actions for public repos), container stdout collectors, and any log-shipping pipeline.
For a key-generation utility this is the single most damaging default: the tool's one job is to
produce a secret, and it broadcasts it.

**Action.** Never print or log private key material. Print the *public* key only on explicit
`--show-public`. Emit the private key path and a fingerprint instead. If a "print to stdout"
mode is genuinely needed for piping, gate it behind `--private-key-to-stdout` with a TTY check
and a loud warning, and suppress all file writing in that mode.

---

#### C4 — Private key stored unencrypted, with no passphrase option

`main.py:54`:
```python
encryption_algorithm = (serialization.NoEncryption(),)  # Use a passphrase if needed
```
The comment invites a passphrase; no code path provides one.

**Impact.** The at-rest key is plaintext PEM. Combined with C2, compromise requires only read
access to the filesystem.

**Action.** Add `--passphrase-env VAR` / `--passphrase-file PATH` (never a bare `--passphrase`
argv flag — argv is world-visible in `/proc`). Use
`serialization.BestAvailableEncryption(passphrase)`. Consider defaulting to *requiring* a
passphrase with an explicit `--no-passphrase` opt-out.

---

#### C5 — `write_text_in_binary_mode*` fails on every documented call *[verified]*

`utils/checks/checks.py:39` rejects any argument that is not a `str`:
```python
if arg is None or not isinstance(arg, str) or len(arg.strip()) == 0:
```
`utils/io/write_file.py:42` passes the payload through it:
```python
if checks.str_none_or_empty(directory, file_name, text):
```
but `text` is documented as `bytes` (`write_file.py:27`) and the file is opened `"wb"`.

Verified:
```
str_none_or_empty(b'test data')  ->  True
write_text_in_binary_mode('.', 'out.bin', b'test data')
  -> Exception: One or more arguments are empty
```

The module's own docstring example (`write_file.py:37`) cannot execute successfully. The
function has a **100% failure rate for its intended use**.

**Why no test caught it.** `tests/utils/io/test_write_file.py:14` patches
`checks.str_none_or_empty` itself, replacing the defect with `return False`. The tests assert
that mocks were called, not that the code works. This is the clearest possible demonstration
that the 97% coverage figure measures line execution, not correctness.

**Action.** Split validation: `str_none_or_empty` for path components only; a separate
`bytes`-aware guard (or none — let `open()` raise) for the payload. Add an unmocked
`tmp_path` round-trip test that would have caught this.

---

#### C6 — Re-running silently destroys an existing private key

`main.py:65-73` — `mkdir(exist_ok=True)` then `open(..., "wb")` truncates.

**Impact.** A second invocation in the same working directory overwrites `private-key.pem` with
no prompt, no backup, and no error. If that key was already distributed, trusted, or used to
encrypt data, the data becomes permanently unrecoverable. There is no undo.

**Action.** Open with `O_EXCL` so an existing file is a hard error; require explicit `--force`
to replace, and on `--force` rename the old key to `private-key.pem.bak-<timestamp>` (mode 0600)
rather than deleting it.

---

### 1.2 High

---

#### H1 — The package implements none of the functionality its name and metadata promise

Named `encryption-helper`; keywords declare `"encryption", "decryption"`;
`common/strings.py:24` defines `encrypted_file_suffix = ".bin"`. There is **no encrypt
function, no decrypt function**, and nothing that consumes `.bin`. The package generates one
kind of key pair and stops.

Absent, in rough priority order: encrypt/decrypt, key loading from disk, sign/verify,
fingerprinting, format conversion (PEM↔DER↔OpenSSH), non-RSA algorithms (Ed25519, ECDSA
P-256/384), CSR generation, self-signed certificate generation, key rotation.

**Action.** See §2, Phase 3. Note that RSA cannot encrypt arbitrary-length data — the correct
design is hybrid envelope encryption (AES-256-GCM content key, wrapped with RSA-OAEP-SHA256),
not naive `public_key.encrypt(plaintext)`. Getting this wrong is the most common way a
"helper" library becomes a vulnerability.

---

#### H2 — `utils/io` and `common/strings` are dead code *[verified]*

`main.py` writes with raw `open()` (lines 68, 72) rather than `write_text_in_binary_mode`.
`read_file.py` has no callers anywhere in `encryption_helper/`. `strings.py` constants are
imported only by their own test.

That is ~110 LOC of source and ~230 LOC of tests maintained for code the package does not use —
and the unused code is the broken code (C5). Dead code that is 100% "covered" by tests actively
inflates the quality metrics.

**Action.** Either wire the IO layer into `main.py` (after fixing C5) or delete it. Given the
secure-write requirements of C2, the right move is to replace it with a single hardened
`io_.secure_write_bytes()` and delete the rest.

---

#### H3 — Constant disagrees with the filename actually written

`common/strings.py:19` `public_key_suffix = "public_key.pem"` (underscore)
`main.py:72` writes `"public-key.pem"` (hyphen)
`.gitignore` ignores `public-key.pem` (hyphen)
`tests/common/test_strings.py:18` asserts the **underscore** form, locking in the wrong value.

**Action.** Standardise on the hyphenated form, fix the constant, fix the test, and make
`main.py` consume the constant so the two cannot drift again.

---

#### H4 — Zero CLI surface in a self-described "CLI application"

`__main__.py` takes no arguments. No `argparse`, no `click`. No `--help` beyond nothing, no
`--version`, no `--out-dir`, `--key-size`, `--format`, `--passphrase`, `--force`, `--quiet`,
`--log-level`, `--json`.

Output location is hardcoded CWD-relative (`main.py:64` `Path("keys/pem")`), so running the tool
from different directories scatters `keys/pem/` trees across the filesystem.

**Action.** Phase 4: a real command tree with subcommands, exit codes, and `--help` text.

---

#### H5 — Key size and algorithm hardcoded

`main.py:47` `key_size=2048`, RSA only, `public_exponent=65537`.

2048-bit RSA is acceptable today but is on the wrong side of the curve for keys with a long
validity horizon; guidance increasingly favours ≥3072 for new material. The README's
"Configuration" section tells users to *edit the source*.

**Action.** `--key-size {2048,3072,4096}` defaulting to 3072, plus `--algorithm
{rsa,ed25519,ecdsa-p256,ecdsa-p384}`. Reject <2048 outright.

---

#### H6 — The test suite is over-mocked; its coverage number is not evidence of correctness *[verified]*

34 tests pass. Line coverage of `encryption_helper/` is **97%** (152 statements, 4 missed).
Yet C5 — a total, unconditional failure of a public function — is invisible to it.

Specific defects:
- `tests/test_main.py` mocks `rsa.generate_private_key`, `Path.mkdir`, and `open`. **No test
  ever generates a real key or writes a real file.** The one function that matters is never
  actually exercised.
- `tests/utils/io/*` mock `checks.str_none_or_empty` — i.e. they mock away the bug.
- `tests/test_main.py:9` patches `serialization.load_pem_private_key`, which the code under test
  never calls. Vestigial.
- `tests/test_main.py:56-61` calls `generate_rsa_key()` a *second* time inside the first test to
  assert on prints — two behaviours, one test, order-dependent.
- `tests/context/test_context.py:10` mutates the private `Context._instance` to work around the
  singleton (see M8).
- Style is `unittest`, yet `pytest-mock` is a declared dependency and its `mocker` fixture is
  never used anywhere.
- No `conftest.py`; mock-logger boilerplate is copy-pasted ~8 times.
- No integration test, no round-trip test (generate → load → sign → verify), no `tmp_path`
  filesystem tests, no permission assertions, no branch coverage, no coverage threshold in CI.

**Action.** Phase 5 — rewrite. Target: ≥95% *branch* coverage with mocks used only for
failure-injection, plus a real end-to-end test that generates a key on disk and asserts mode
0600.

---

#### H7 — `.pylintrc` disables all checks; the 10/10 CI score is meaningless *[verified]*

`.pylintrc` contains `disable=all` followed by a hand-picked `enable=` allowlist.

| Run | Score |
|---|---|
| CI config (`.pylintrc`) | **10.00/10**, 0 errors |
| Default ruleset (`--rcfile=/dev/null`) | **9.34/10**, 11 messages |

The 11 suppressed real findings: `W0718` broad-exception-caught (`__main__.py:38`), `W0719`
broad-exception-raised ×4 (`read_file.py:43,73`, `write_file.py:44,75`), `C0209`
consider-using-f-string ×2, `C0103` invalid-name ×3 (`strings.py`).

The rcfile is also **stale and syntactically broken**:
- `E0015 unrecognized-option` — 13 dead options: `optimize-ast`, `files-output`,
  `const-name-hint`, `class-name-hint`, `argument-name-hint`, `variable-name-hint`,
  `class-attribute-name-hint`, `method-name-hint`, `module-name-hint`, `function-name-hint`,
  `attr-name-hint`, `inlinevar-name-hint`, `no-space-check`
- `W0012 unknown-option-value` ×5 — `E0116`, `C1001`, `W0110`, `W0623` are not valid message IDs
- `R0022 useless-option-value` — `R0201` was moved to an optional extension
- **Missing comma** between `W1307` and `R0102` — pylint parses them as the single token
  `W1307\n        R0102`, so `R0102` is silently not enabled
- **Stray double comma** `,,W1305` in the `W13xx` group

**Action.** Delete `.pylintrc` entirely and adopt **Ruff** (which subsumes flake8, isort,
pyupgrade, pydocstyle, bandit-equivalent rules and much of pylint) with an explicit,
minimal `ignore` list. Keep pylint only if the team wants its inference checks, and then
configure it in `pyproject.toml` with `disable` listing specific codes — never `all`.

---

#### H8 — Security tooling is configured but never executed

`.bandit.yml` exists and is well-formed; **no workflow invokes bandit**. Verified: running it
manually reports zero issues over 420 LOC — a result no one has ever seen in CI.

Also absent: CodeQL, `dependency-review-action`, `pip-audit`/`safety`, secret scanning /
push protection, OpenSSF Scorecard, SBOM generation (CycloneDX/SPDX), signed releases,
build provenance attestation.

`.bandit.yml` additionally excludes `tests/*` from scanning.

---

#### H9 — CI workflows are unhardened and partly redundant

`.github/workflows/pylint.yml` and `python-package.yml`:

- **No `permissions:` block.** Workflows inherit the repository default token scope; there is no
  least-privilege declaration.
- **Actions pinned to mutable tags** (`actions/checkout@v6`, `actions/setup-python@v6`) rather
  than commit SHAs — a tag can be repointed by a compromised upstream.
- **No `concurrency:` group**, so superseded pushes keep burning runners.
- **No `timeout-minutes:`** — a hung job can occupy a runner for 6 hours.
- **No dependency caching** (`cache: 'pip'` on setup-python).
- **Inconsistent triggers:** `pylint.yml` fires `on: [push]` for *every* branch; `python-package.yml`
  only on `main` push/PR.
- **Duplicated setup** across two workflows that could be one matrix job.
- **The flake8 gate is a no-op:** the second invocation passes `--exit-zero`, and it uses
  `--max-line-length=127` while `.flake8` says `79` — so CI and local linting disagree by design.
- No test on Windows or macOS despite the `Operating System :: OS Independent` classifier — and
  file-permission behaviour (C2) is exactly where platforms diverge.

---

#### H10 — Python 3.8 is EOL and the support matrix is two releases behind

`pyproject.toml:23` `python = "^3.8"` · `setup.py:46` `python_requires=">=3.8"`
CI matrix: `3.8, 3.9, 3.10, 3.11, 3.12` (pylint workflow: only `3.8, 3.9, 3.10`)
Classifiers stop at 3.12.

Python 3.8 reached end-of-life in October 2024 — it receives no security patches. Meanwhile
3.13 and 3.14 are untested (this analysis ran on 3.14.7).

**Action.** Drop 3.8 and 3.9. Set `requires-python = ">=3.10"`. Test `3.10–3.14`. Update
classifiers to match exactly. Doing so also unlocks modern syntax (`X | Y` unions, `match`).

---

### 1.3 Medium

| ID | Finding | Evidence |
|----|---------|----------|
| **M1** | **Version declared in three places** plus a test — `__init__.py:20`, `pyproject.toml:3`, `setup.py:15`, asserted at `tests/test___init__.py:12`. Guaranteed to drift. Fix: single source in `pyproject.toml`, read via `importlib.metadata.version()`. | 4 locations |
| **M2** | **Dual packaging.** `setup.py` and Poetry `pyproject.toml` both declare name/version/deps/entry-points **and disagree**: setup.py says `cryptography>=43.0.0` (unbounded), Poetry says `^43.0.0` (capped `<44`). Build backend is `poetry-core`, so `setup.py` is inert but actively misleading. `setup_requires=["build"]` is legacy and wrong. Fix: delete `setup.py`; migrate to PEP 621 `[project]`. | `setup.py`, `pyproject.toml` |
| **M3** | **Deprecated + duplicated dep groups.** `[tool.poetry.dev-dependencies]` (deprecated) *and* `[tool.poetry.group.dev.dependencies]` both present, listing `pytest` and `pytest-mock` twice. Worse, `setuptools = "^75.0.0"` is declared a **runtime** dependency — nothing imports it. | `pyproject.toml:27-39` |
| **M4** | **`requirements.txt` is a 102-line hash-pinned Poetry export** that duplicates `poetry.lock` — and is what CI actually installs, so CI and Poetry can silently diverge. No documented regeneration step. | `requirements.txt`, `python-package.yml` |
| **M5** | **SECURITY.md is the unedited GitHub template.** Claims supported versions `5.1.x` / `4.0.x` for a `0.0.1` project. Retains placeholder prose ("Use this section to tell people…"). No reporting address, no response SLA, no PGP key, no GitHub private vulnerability reporting. On a bank's public cryptography repo this is conspicuous. | `SECURITY.md` |
| **M6** | **Missing community health files:** no `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `CHANGELOG.md`, `CODEOWNERS`, `SUPPORT.md`, issue templates, PR template, `.editorconfig`, `.pre-commit-config.yaml`, `.gitattributes`. | `.github/` has only 2 workflows |
| **M7** | **No typing rigor.** `utils/io/*`, `utils/checks/*`, `common/strings.py` are entirely unannotated. No `py.typed` marker, so downstream consumers get *no* types even from the annotated `main.py`. No mypy/pyright config or CI step. `Context.get_logger` returns an `Optional[Logger]` attribute as `Logger` (`context.py:158`) — a strict-mode error. | package-wide |
| **M8** | **`Context` singleton is structurally unsound.** State declared as **class** attributes (`context.py:38-41`), so it is process-global mutable state, not instance state. `get_instance` is check-then-act — **not thread-safe** (`context.py:68-70`). `init_logging` builds a `StreamHandler` then discards it if handlers already exist (`context.py:131,137`). The logger propagates to root, double-logging in any host app that configures logging. No reset path — tests must poke `Context._instance = None`. The whole class reimplements, worse, what `logging.getLogger(__name__)` already does. Fix: delete it. | `context/context.py` |
| **M9** | **Generic exceptions.** `raise Exception(...)` ×4 (`read_file.py:43,73`, `write_file.py:44,75`) — callers cannot catch precisely without matching on message strings. `except Exception` in `main.py:90` and `__main__.py:38`. No package exception hierarchy. Fix: `EncryptionHelperError` base + `KeyGenerationError`, `KeyWriteError`, `InvalidArgumentError`, `KeyExistsError`. | 6 sites |
| **M10** | **Eager log formatting.** f-strings/`.format()` inside logging calls (`main.py:76-77`, `read_file.py:75`, `write_file.py:77`) are evaluated even when the level is disabled, and defeat structured-logging aggregation. Use `logger.debug("...%s", value)`. | 4 sites |
| **M11** | **A library function prints to stdout.** `main.py:80-83`. Presentation belongs in `__main__.py`/`cli.py`. As written, `generate_rsa_key()` is unusable from a service without capturing stdout — and see C3. | `main.py:80-83` |
| **M12** | **flake8 config weakens itself.** `.flake8` ignores `F401` (unused import) and `F403` (star import) — real bug classes — plus `E501`. `exclude = tests/*` leaves all test code unlinted. And CI overrides the config with different inline flags. | `.flake8` |
| **M13** | **No enforced formatter.** No black/ruff-format config; formatting is convention-only. Three `W291` trailing-whitespace violations currently in tree. | `checks.py:4`, `read_file.py:4`, `write_file.py:4` |
| **M14** | **`keys/` directory is committed** to the repo, containing `keys/README.md` (an HSBC logo and nothing else) and a **0-byte** `keys/pem/README.md`. Shipping a `keys/` folder inside a source checkout trains users to keep real private keys in a git working tree. `.gitignore` catches `*-key.pem`, which mitigates but does not remove the footgun — and does not catch `*.key`, `*.p12`, `*.pfx`, `*_key.pem`. | `keys/` |
| **M15** | **Documentation gaps.** No badges (build, coverage, PyPI, license, Python versions). **README is factually wrong**: the Configuration section states `Standard: PKCS#1` while `main.py:53` emits `PrivateFormat.PKCS8`. No API reference, no security guidance on protecting the generated key, no threat model, no "not a substitute for an HSM" caveat, no troubleshooting, no versioning policy, no examples dir. Docs advice is `pydoc -w` rather than a real docs site. | `README.md` |
| **M16** | **Never released.** Zero git tags, zero GitHub releases, absent from PyPI, no publish workflow, no signed tags, no build provenance. README offers only clone-and-install; `pip install encryption-helper` does not work. | `git tag` → empty |
| **M17** | **Project is dormant.** Last change to `encryption_helper/` or `tests/` — **2024-07-27**. Every one of the 80+ commits since is a Renovate bump; 32 of 86 total commits are the bot. The most recent "human" commit (2025-09-22) is a merge of a bot PR. | `git log` |
| **M18** | **Maintainer contact is a personal corporate address.** `sebastien.rousseau-bedouch@hsbc.com` in `pyproject.toml:5` and `setup.py:17`. Bus factor of one, and it publishes an individual employee's internal address on PyPI. A team alias already exists in the history (`opensource@hsbc.com`). | 2 locations |

### 1.4 Low

- **L1** — Four `__init__.py` files are 0 bytes with no docstring (`common/`, `utils/`, `utils/io/`, `utils/checks/`), inconsistent with the documented `context/__init__.py`. (pydocstyle D104)
- **L2** — `keys/pem/README.md` is a 0-byte file used as a directory placeholder; `.gitkeep` is the convention.
- **L3** — `assets/banner.jpg` uses JPEG for what is likely flat graphic art; PNG/WebP/SVG would be smaller and sharper.
- **L4** — No `--version` flag and no meaningful `--help`.
- **L5** — No `.gitattributes`, so line endings are not normalised across contributors.
- **L6** — `keys/README.md` contains only a remote-hosted HSBC logo image and no explanatory text about what the directory is for or the risk of putting keys in it.
- **L7** — Renovate uses bare `config:recommended` with no grouping, no schedule, no automerge policy for patch-level dev-dependency bumps — which is why the history is 37% bot noise.

---

## 2. Implementation plan

Eight phases. Phases 0–1 are prerequisites for everything else; 2–7 are largely parallelisable
after Phase 1 lands. Effort figures are rough engineer-days for one developer familiar with the
codebase.

### Dependency graph

```
Phase 0 (legal/security triage)  ──┐
Phase 1 (foundation: tooling)    ──┼──> Phase 2 (core rewrite) ──> Phase 3 (features)
                                   │                            └─> Phase 4 (CLI)
                                   ├──> Phase 5 (tests)   [follows 2/3/4 incrementally]
                                   ├──> Phase 6 (CI/CD & supply chain)
                                   └──> Phase 7 (docs & governance) ──> Phase 8 (release)
```

---

### Phase 0 — Legal & security triage *(blocking, ~1 day + external turnaround)*

Nothing else should merge until these are resolved; they change what the project *is*.

| # | Task | Acceptance criteria |
|---|------|---------------------|
| 0.1 | **Resolve the license contradiction (C1).** Raise with HSBC Open Source / legal. Determine whether Apache-2.0 (the file) or MIT (the metadata) is intended. | Written decision recorded in the PR. All five locations agree. If Apache-2.0: add `NOTICE`, add SPDX headers `# SPDX-License-Identifier: Apache-2.0` to every source file. GitHub's detected license matches the metadata. |
| 0.2 | **Security advisory for C2/C3.** Any key generated by v0.0.1 must be treated as potentially compromised — it was world-readable and echoed to stdout. | A `SECURITY-ADVISORY.md` (or GHSA) stating: keys produced by ≤0.0.1 should be rotated. Linked from README and CHANGELOG. |
| 0.3 | **Replace `SECURITY.md` (M5).** | Real reporting channel (GitHub private vulnerability reporting enabled + `opensource@hsbc.com`), 48h acknowledgement / 90-day disclosure SLA, accurate supported-version table, optional PGP key. Zero template placeholder text remains. |
| 0.4 | **Confirm maintainer contact (M18).** | `pyproject.toml` author email is a team alias, not an individual. `CODEOWNERS` names a team. |

---

### Phase 1 — Foundation: tooling, packaging, typing *(~2 days)*

| # | Task | Acceptance criteria |
|---|------|---------------------|
| 1.1 | **Migrate to PEP 621.** Convert `[tool.poetry]` → `[project]`. Delete `setup.py` (M2). Choose one backend — recommend Hatchling for a pure-Python package, or keep `poetry-core` if the team standardises on Poetry. | `pyproject.toml` has a single `[project]` table. `setup.py` gone. `python -m build` produces a valid sdist + wheel. `twine check dist/*` passes. |
| 1.2 | **Single-source the version (M1).** Version lives only in `[project].version` (or is derived from git tags via `hatch-vcs`). `__init__.py` uses `importlib.metadata.version("encryption-helper")`. | `grep -rn '0\.0\.' --include='*.py' --include='*.toml'` returns exactly one hit. The version test asserts consistency between `__version__` and installed metadata, not a hardcoded literal. |
| 1.3 | **Clean dependencies (M3).** Remove the deprecated `[tool.poetry.dev-dependencies]` block and the duplicate pytest entries. **Remove `setuptools` from runtime deps.** Widen `cryptography` to `>=43,<100` or track latest with a documented floor. | One dev-dependency group. `pip install encryption-helper` pulls only `cryptography`. |
| 1.4 | **Delete `requirements.txt` (M4)** and have CI install via the lockfile. If a pinned export is needed for a downstream consumer, generate it in CI and attach it to releases rather than committing it. | CI installs from `poetry.lock`/`uv.lock`. No hand-maintained pin file in the tree. |
| 1.5 | **Drop Python 3.8/3.9 (H10).** `requires-python = ">=3.10"`. Update classifiers to `3.10`–`3.14` exactly. | Classifiers, `requires-python`, and the CI matrix are identical sets. |
| 1.6 | **Adopt Ruff; delete `.pylintrc` and `.flake8` (H7, M12, M13).** Configure `[tool.ruff]` in `pyproject.toml` with an explicit rule selection (`E,W,F,I,N,D,UP,B,A,C4,S,BLE,LOG,G,PTH,RET,SIM,ARG,PL,RUF`) and a short, *justified* `ignore` list. Enable `ruff format`. **Lint `tests/` too.** | `ruff check .` and `ruff format --check .` both clean on the whole tree including tests. No `disable=all` anywhere. The three `W291` violations are gone. |
| 1.7 | **Add mypy in strict mode + `py.typed` (M7).** | `mypy --strict encryption_helper` passes with zero errors and zero `# type: ignore` without an explanatory comment. `py.typed` is included in the wheel (verified by unzipping the artifact). |
| 1.8 | **Add `.pre-commit-config.yaml`** wiring ruff, ruff-format, mypy, and `detect-private-key`. Add `.editorconfig` and `.gitattributes`. | `pre-commit run --all-files` passes. `detect-private-key` is active — directly relevant given M14. |
| 1.9 | **Harden `.gitignore` (M14).** Add `*.key`, `*.pem`, `*.p12`, `*.pfx`, `*.jks`, `!**/testdata/*.pem`. | No plausible key extension can be committed accidentally. |

---

### Phase 2 — Core rewrite: security, structure, correctness *(~3 days)*

This is where C2–C6, H2, M8–M11 are resolved.

**Target layout:**
```
encryption_helper/
├── __init__.py          # curated public API; __version__ via importlib.metadata
├── __main__.py          # 3 lines: from .cli import main; raise SystemExit(main())
├── cli.py               # argument parsing, output formatting, exit codes
├── errors.py            # EncryptionHelperError hierarchy
├── _io.py               # secure_write_bytes(), atomic_replace(), read_bytes()
├── keys/
│   ├── generate.py      # generate_rsa, generate_ed25519, generate_ecdsa
│   ├── load.py          # load_private_key, load_public_key
│   ├── serialize.py     # PEM/DER/OpenSSH encode+decode
│   └── fingerprint.py   # SHA-256 fingerprints (OpenSSH-compatible)
├── crypto/
│   ├── envelope.py      # hybrid encrypt/decrypt
│   └── signing.py       # sign / verify (RSA-PSS, Ed25519)
└── py.typed
```

| # | Task | Acceptance criteria |
|---|------|---------------------|
| 2.1 | **`errors.py` (M9).** `EncryptionHelperError(Exception)` base; `KeyGenerationError`, `KeyWriteError`, `KeyReadError`, `KeyExistsError`, `InvalidArgumentError`, `DecryptionError`. Replace all four `raise Exception(...)` and both bare `except Exception`. | `ruff` rules `BLE001`/`TRY002` clean. No `raise Exception` or bare `except Exception` outside the CLI's top-level handler. |
| 2.2 | **`_io.secure_write_bytes(path, data, *, mode=0o600, overwrite=False)` (C2, C6).** Uses `os.open(..., O_WRONLY\|O_CREAT\|O_EXCL, mode)`; writes to a temp file in the same directory then `os.replace()` for atomicity; `KeyExistsError` if the target exists and `overwrite=False`; on overwrite, back up to `<name>.bak-<ISO8601>` at 0600. Parent dirs created at 0700. Documented Windows ACL fallback. | Unit test asserts `stat().st_mode & 0o777 == 0o600` on POSIX. Test asserts `KeyExistsError` on a second write. Test asserts a partial write leaves no truncated target. Windows path covered or explicitly `skipif`-ed with a tracking issue. |
| 2.3 | **Delete `context/` (M8).** Replace with module-level `logger = logging.getLogger(__name__)`. The library adds a `NullHandler` and configures **nothing**; `cli.py` owns `logging.basicConfig`. | `Context` no longer exists. No global mutable state. `tests/context/` deleted. No test manipulates a private attribute. |
| 2.4 | **Delete `utils/io/`, `utils/checks/`, `common/strings.py` (H2, C5, H3).** Their responsibilities move to `_io.py` and module constants. If any behaviour is retained, it must be the *fixed* behaviour with a `bytes`-aware guard. | `vulture`/`ruff` report no unreachable public functions. The C5 reproduction (`write_text_in_binary_mode('.', 'x', b'data')`) either works or the function is gone. Filename constants are used by the writer, not just asserted by a test. |
| 2.5 | **Rewrite `generate_rsa_key` → `keys.generate` (C3, C4, C5, H5, M10, M11).** New signature: `generate_rsa(*, key_size: int = 3072, public_exponent: int = 65537) -> RSAPrivateKey`. **Returns the key object; performs no IO, no printing, no logging of secrets.** Serialization and writing are separate, composable steps. Passphrase support via `BestAvailableEncryption`. | No `print()` anywhere under `encryption_helper/` except `cli.py`. `grep -rn 'private_key' encryption_helper/ \| grep -i 'print\|logger\.\(debug\|info\)'` returns nothing. `key_size < 2048` raises `InvalidArgumentError`. Lazy `%s` logging throughout. |
| 2.6 | **Fix the PKCS mismatch (M15).** Code emits PKCS#8; either keep PKCS#8 (correct, modern) and fix the README, or expose `--format {pkcs8,pkcs1}`. Recommend the former plus an explicit note. | README's stated standard matches `serialization.PrivateFormat` in the code. |
| 2.7 | **Add docstrings to the four empty `__init__.py` (L1).** | pydocstyle `D104` clean. |

---

### Phase 3 — Feature completion *(~4 days)*

Closes H1 — makes the package match its name.

| # | Task | Acceptance criteria |
|---|------|---------------------|
| 3.1 | **`keys/load.py`** — `load_private_key(path, passphrase=None)`, `load_public_key(path)`. Auto-detect PEM/DER/OpenSSH. | Round-trip test: generate → write → load → compare public numbers. Wrong-passphrase raises `KeyReadError`, not a raw `cryptography` exception. |
| 3.2 | **`crypto/envelope.py` — hybrid encryption.** `encrypt(public_key, plaintext) -> bytes` generating a random AES-256 key, encrypting content with **AES-256-GCM**, wrapping the content key with **RSA-OAEP (SHA-256, MGF1-SHA256)**, and emitting a versioned, self-describing container (magic bytes + version + algorithm IDs + nonce + wrapped key + ciphertext + tag). `decrypt(private_key, blob) -> bytes`. | Round-trip over 0 B, 1 B, 1 MiB, and 100 MiB payloads. Tamper tests: flipping any byte of ciphertext, tag, nonce, or wrapped key raises `DecryptionError` and never returns plaintext. Container version field is validated. **Never** exposes raw `public_key.encrypt()` for arbitrary-length input. |
| 3.3 | **`crypto/signing.py`** — `sign(private_key, data)` / `verify(public_key, sig, data)` using RSA-PSS (SHA-256, salt = digest length) and Ed25519. | Known-answer tests. `verify` returns `False` / raises on tamper — never silently passes. |
| 3.4 | **`keys/fingerprint.py`** — OpenSSH-compatible `SHA256:<base64>` fingerprints. | Output byte-identical to `ssh-keygen -lf` for the same key (test against a committed fixture, cross-checked once by hand). |
| 3.5 | **Additional algorithms (H5)** — Ed25519 and ECDSA P-256/P-384 generation, serialization, signing. | Each algorithm has generate → write → load → sign → verify coverage. |
| 3.6 | **Format conversion** — PEM ↔ DER ↔ OpenSSH for public keys; PKCS#8 ↔ OpenSSH for private keys. | Conversion is lossless and round-trips through `ssh-keygen` where applicable. |
| 3.7 | *(Optional, scope permitting)* CSR and self-signed certificate generation. | Output validates under `openssl req -verify` / `openssl x509 -text`. |

---

### Phase 4 — CLI *(~2 days)*

Closes H4, L4.

| # | Task | Acceptance criteria |
|---|------|---------------------|
| 4.1 | **Subcommand tree** (`argparse` — zero extra deps — or `click`/`typer` if a richer UX is wanted): `keygen`, `encrypt`, `decrypt`, `sign`, `verify`, `fingerprint`, `convert`. | `--help` for the root and every subcommand is accurate and example-bearing. |
| 4.2 | **Global flags:** `--version`, `-v/--verbose` (repeatable), `-q/--quiet`, `--log-level`, `--json` (machine-readable output). | `--version` prints the installed metadata version. `--json` emits schema-stable objects on stdout with all human text on stderr. |
| 4.3 | **`keygen` flags (C4, C6, H4, H5):** `--algorithm`, `--key-size`, `--out-dir` (default `.`, **not** `keys/pem`), `--name`, `--format`, `--passphrase-env`, `--passphrase-file`, `--force`, `--show-public`. **No `--passphrase` taking a literal value** — argv is visible in `/proc` and shell history. | Passphrase never appears in argv. `--out-dir` default no longer creates a surprise `keys/pem/` tree in the CWD. `--force` is required to overwrite and produces a backup. |
| 4.4 | **Exit codes:** `0` success, `1` generic, `2` usage error, `3` key exists, `4` decryption/verification failure. Documented in README and `--help`. | Each code is asserted by a CLI test. |
| 4.5 | **stdin/stdout streaming** for `encrypt`/`decrypt` (`--in -` / `--out -`) so the tool composes in pipelines. | `cat f \| encryption-helper encrypt --public-key k.pem --in - --out - \| ...` round-trips. Binary-safe on Windows. |
| 4.6 | **A prominent warning on `keygen`** that the private key is a secret, plus the resolved path and fingerprint on success — replacing C3's key dump. | Output contains the path and fingerprint, and no PEM body. |

---

### Phase 5 — Test suite rewrite *(~3 days)*

Closes H6. This runs alongside phases 2–4, not after.

| # | Task | Acceptance criteria |
|---|------|---------------------|
| 5.1 | **Convert to pytest idiom.** Plain functions, `pytest.raises`, parametrisation. A `conftest.py` supplying shared fixtures (`tmp_keydir`, `rsa_key`, `ed25519_key`, `caplog`) to kill the ~8 duplicated mock-logger blocks. | No `unittest.TestCase` remains. `pytest-mock`'s `mocker` is used or the dependency is dropped. |
| 5.2 | **Delete the mock-the-unit-under-test antipattern (C5's cover).** Mocks are permitted **only** to inject failures (e.g. `OSError` from `os.open`) — never to replace the function being asserted. | No test patches `str_none_or_empty`, `open`, or `rsa.generate_private_key` for a happy-path assertion. The vestigial `load_pem_private_key` patch is gone. `tests/test_main.py`'s double-invocation test is split in two. |
| 5.3 | **Real filesystem tests** using `tmp_path`: generate → assert file exists → assert **mode 0600** → load → verify the key matches. | This test fails against the current `main.py` (proving it detects C2) and passes after Phase 2. |
| 5.4 | **Regression test for C5** — an unmocked `write` round-trip with `bytes` payload. | Fails on the v0.0.1 code; passes after the fix. |
| 5.5 | **Property-based tests** (`hypothesis`) for the envelope format: arbitrary `bytes` round-trip; arbitrary single-byte mutation of the container never yields plaintext. | ≥1000 examples per property in CI, seeded and reproducible. |
| 5.6 | **Negative/security tests:** wrong passphrase, truncated container, wrong-key decrypt, tampered tag, `key_size=512` rejected, path traversal in `--out-dir`, symlink-attack on the output path. | All raise typed errors; none leak secret material into the exception message. |
| 5.7 | **CLI tests** for every subcommand, flag, and exit code, via `subprocess` against the installed console script (not just an in-process call). | Console-script entry point is proven to work as installed. |
| 5.8 | **Cross-platform CI tests** — Linux, macOS, Windows. | Permission assertions are platform-aware, not skipped silently. |
| 5.9 | **Coverage gate:** `--cov-branch`, `fail_under = 95`. | CI fails below the threshold. Coverage is reported on *branch*, not line. |
| 5.10 | **Mutation testing** (`mutmut` or `cosmic-ray`) on `crypto/` and `keys/`, run on a schedule rather than per-PR. | ≥85% mutation score on the crypto modules — the metric that would actually have caught C5. |

---

### Phase 6 — CI/CD & supply chain *(~2 days)*

Closes H8, H9.

| # | Task | Acceptance criteria |
|---|------|---------------------|
| 6.1 | **Consolidate into `ci.yml`** — one workflow, jobs: `lint` (ruff + format check), `type` (mypy strict), `test` (OS × Python matrix), `security`, `build`. Delete `pylint.yml`. | Two workflows become one coherent pipeline. No duplicated setup steps. |
| 6.2 | **Harden every workflow (H9):** top-level `permissions: contents: read` with per-job escalation only where needed; **all actions pinned to full commit SHAs** with a version comment; `concurrency: group: ${{ github.workflow }}-${{ github.ref }}, cancel-in-progress: true`; `timeout-minutes` on every job; `cache: 'pip'`. | `zizmor` / `actionlint` clean. No mutable action refs. |
| 6.3 | **Real lint gates.** Remove `--exit-zero`. One config (`pyproject.toml`) drives both local and CI linting. | It is impossible for CI to pass with a lint error. Local and CI produce identical results. |
| 6.4 | **Wire up bandit (H8)** — actually run it, and stop excluding `tests/`. | Bandit runs on every PR and fails the build on any finding. |
| 6.5 | **Add CodeQL** (`python` + `actions` queries), `dependency-review-action` on PRs, and `pip-audit` on a schedule. | All three report into the Security tab. `pip-audit` failure blocks release. |
| 6.6 | **OpenSSF Scorecard** workflow with results published. | Scorecard ≥8.0. Branch protection, code review, and pinned-dependency checks pass. |
| 6.7 | **SBOM** (CycloneDX) generated per build and attached to releases. | Every release asset set includes an SBOM. |
| 6.8 | **Release workflow** — tag-triggered, PyPI **Trusted Publishing** (OIDC, no long-lived token), `actions/attest-build-provenance`, GitHub Release with generated notes. | `git tag v0.1.0 && git push --tags` publishes a signed, attested release with no human secret handling. |
| 6.9 | **Tune Renovate (L7)** — group minor/patch dev-dependency bumps, weekly schedule, automerge patch-level dev deps after CI passes. | Bot commit volume drops materially; the history stops being 37% noise. |
| 6.10 | **Enable branch protection** on `main`: required status checks, required review, linear history, no force-push, signed commits. | Documented in `CONTRIBUTING.md`. |

---

### Phase 7 — Documentation & governance *(~2 days)*

Closes M6, M15, L2, L3, L6.

| # | Task | Acceptance criteria |
|---|------|---------------------|
| 7.1 | **Rewrite README.** Badges (CI, coverage, PyPI, Python versions, license, Scorecard). Correct the PKCS#1→PKCS#8 error. Real `pip install encryption-helper` instructions. Quickstart per subcommand. Full CLI reference. Library-usage examples. | Every command block in the README is executed by a docs test (`pytest --doctest-glob` or `mdformat`-based runner) and passes. |
| 7.2 | **Add a Security Considerations section** — how to protect the generated private key, why passphrases matter, filesystem permissions, an explicit **"this is not an HSM/KMS replacement"** caveat, and a short threat model. | Reviewed and signed off by whoever owns 0.2. |
| 7.3 | **`CONTRIBUTING.md`** — dev setup, pre-commit, test/lint commands, conventional-commit convention, review expectations, release process. | A new contributor can go from clone to green local test run using only this file. |
| 7.4 | **`CODE_OF_CONDUCT.md`** (Contributor Covenant 2.1) with a real enforcement contact. | Present, with a working contact address. |
| 7.5 | **`CHANGELOG.md`** (Keep a Changelog), retroactively covering 0.0.1 and documenting every breaking change plus the C1–C6 fixes and the key-rotation advisory. | A user upgrading from 0.0.1 can determine exactly what broke and that they must rotate keys. |
| 7.6 | **`CODEOWNERS`, `SUPPORT.md`, issue templates** (bug / feature / security-redirect), **PR template** with a checklist. | New issues route to the right template; security reports are redirected to private reporting, not filed publicly. |
| 7.7 | **API docs site** — MkDocs Material + mkdocstrings, published to GitHub Pages. Replaces the `pydoc -w` advice. | Docs build in CI; a broken docstring reference fails the build. |
| 7.8 | **Resolve the `keys/` directory (M14).** Delete it from the repo. If a placeholder is needed, use `.gitkeep`; the CLI creates its output directory at runtime with mode 0700. | No `keys/` in the source tree. The 0-byte `keys/pem/README.md` is gone. |
| 7.9 | **`examples/`** — key generation, envelope encryption, signing, and a passphrase-protected workflow. | Every example runs in CI. |

---

### Phase 8 — Release *(~1 day)*

| # | Task | Acceptance criteria |
|---|------|---------------------|
| 8.1 | Cut `v0.1.0` (see the versioning note in §0) with a signed, annotated tag. | Tag is GPG-signed and CI-verified. |
| 8.2 | Publish to PyPI via Trusted Publishing, with provenance attestation. | `pip install encryption-helper` works from a clean environment on all supported Pythons. |
| 8.3 | Publish the GitHub Release with notes, SBOM, and the key-rotation advisory prominently linked. | Release notes lead with the breaking changes and the advisory. |
| 8.4 | Post-release smoke test in a clean container per supported Python version. | `encryption-helper keygen --help` and a full round-trip succeed everywhere. |

---

## 3. Exit criteria — what 10/10 requires

| Category | Target | Objectively verifiable gate |
|---|---|---|
| Correctness & functionality | 10 | Every public function has an unmocked round-trip test; C5-class defects impossible; mutation score ≥85% on crypto modules |
| Security | 10 | Keys at 0600; never printed/logged; passphrase supported; `O_EXCL` + backup on overwrite; bandit + CodeQL + pip-audit green in CI; Scorecard ≥8.0; published threat model |
| Architecture & API design | 10 | No global mutable state; no dead code; library does no IO-printing; typed exception hierarchy; clean module boundaries |
| Testing | 10 | ≥95% **branch** coverage, gated; property + negative + CLI + cross-platform tests; mocks only for failure injection |
| Packaging & distribution | 10 | Single PEP 621 source of truth; one version location; `py.typed` shipped; published to PyPI with provenance |
| CI/CD & automation | 10 | One hardened pipeline; SHA-pinned actions; least-privilege tokens; all gates blocking; 3 OSes × 5 Pythons |
| Documentation | 10 | Accurate (no PKCS#1 error); badged; API site published; every code block CI-executed; security guidance present |
| Licensing & governance | 10 | License unambiguous and consistent in 5 places; SECURITY.md real; full community health file set |
| Type safety & code quality | 10 | `mypy --strict` clean; `ruff` clean on src **and** tests with a justified ignore list; no `disable=all` |
| Release & maintenance | 10 | Semver tags; CHANGELOG; automated releases; tuned Renovate; named owning team |

## 4. Sequencing recommendation

Phase 0 is genuinely blocking — the license question (C1) may change file headers across the
whole tree, and the security advisory (0.2) should precede any public commit that reveals C2/C3
in the changelog.

Land Phase 1 as one mechanical, review-light PR. Then split Phase 2 into three PRs (errors +
`_io`; delete `Context`; rewrite keygen) so each is independently reviewable — Phase 2 is where
the security fixes live, and they deserve careful review rather than being buried in a large
diff. Phases 3, 4, 6, and 7 can proceed in parallel afterwards. Phase 5 is not a phase in
practice: each PR from Phase 2 onward carries its own tests, and 5.9's coverage gate is switched
on once the suite clears 95%.

**Estimated total: ~20 engineer-days**, excluding external turnaround on the legal question.

## 5. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Legal takes weeks to rule on the license | Medium | Blocks Phase 0 | Proceed with Phases 1–5 on a branch; apply SPDX headers as a final mechanical commit |
| Breaking changes strand existing users | Low (never released to PyPI, so the install base is clone-only) | Medium | CHANGELOG migration guide; keep thin deprecated shims for one minor version |
| Hand-rolling the envelope format introduces a crypto flaw | Medium | **High** | Use only `cryptography` primitives, never raw `_backend`; require external cryptographic review of `crypto/envelope.py` before release; test vectors cross-checked against OpenSSL |
| Windows file-permission parity is hard | High | Medium | Ship POSIX-correct behaviour; explicitly document and test the Windows ACL path; do not silently no-op |
| Scope creep in Phase 3 | High | Medium | 3.7 (CSR/certs) is explicitly optional and deferrable to 0.2.0 |
