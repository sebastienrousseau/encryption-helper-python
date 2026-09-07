#!/usr/bin/env bash
#
# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
#
# Release-candidate verification against a clean wheel install.
#
# This script exists because of a specific failure that happened during
# development: an editable install was left pointing at a throwaway clone, so a
# full "all tests passed" run was silently exercising the wrong tree. Every
# release gate below therefore records its provenance first and asserts that
# the package under test is the installed wheel -- never an editable install,
# never the working tree.
#
# Usage:
#   scripts/verify-release-candidate.sh [--allow-dirty]
#
# Scratch space defaults to build/ inside the repository rather than $TMPDIR,
# because building and installing into two virtualenvs needs a few hundred MB
# and /tmp is a small tmpfs on many systems. Override with RC_WORKDIR.
#
# Exits non-zero on the first failure. Writes a provenance record to
# build/release-candidate-<sha>.txt for attachment to the remediation review.

set -euo pipefail

ALLOW_DIRTY=0
[[ "${1:-}" == "--allow-dirty" ]] && ALLOW_DIRTY=1

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# --- 1. Provenance -----------------------------------------------------------

echo "=== Provenance ==="
DIRT="$(git status --porcelain)"
if [[ -n "$DIRT" ]]; then
  echo "$DIRT"
  if [[ "$ALLOW_DIRTY" -eq 0 ]]; then
    echo "ERROR: working tree is not clean. A release candidate must be an" >&2
    echo "       exact commit. Commit or stash, or pass --allow-dirty." >&2
    exit 1
  fi
  echo "WARNING: proceeding with a dirty tree (--allow-dirty)."
fi

HEAD_SHA="$(git rev-parse HEAD)"
HEAD_SHORT="$(git rev-parse --short HEAD)"
BRANCH="$(git rev-parse --abbrev-ref HEAD)"
echo "commit : $HEAD_SHA"
echo "branch : $BRANCH"
echo "clean  : $([[ -z "$DIRT" ]] && echo yes || echo NO)"

mkdir -p build
WORKDIR="$(mktemp -d "${RC_WORKDIR:-$REPO_ROOT/build}/eh-rc-XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT
echo "workdir: $WORKDIR"
AVAIL_KB="$(df -Pk "$WORKDIR" | awk 'NR==2 {print $4}')"
if [[ "$AVAIL_KB" -lt 524288 ]]; then
  echo "ERROR: only $((AVAIL_KB / 1024)) MB free at $WORKDIR; need ~512 MB." >&2
  echo "       Set RC_WORKDIR to a roomier location." >&2
  exit 1
fi

# --- 2. Build from the exact commit -----------------------------------------

echo
echo "=== Build (from a pristine export of $HEAD_SHORT) ==="
git archive --format=tar "$HEAD_SHA" | (mkdir -p "$WORKDIR/src" && tar -x -C "$WORKDIR/src")
python3 -m venv "$WORKDIR/buildenv"
"$WORKDIR/buildenv/bin/pip" install --quiet --upgrade pip build twine
(cd "$WORKDIR/src" && "$WORKDIR/buildenv/bin/python" -m build --outdir "$WORKDIR/dist" >/dev/null)
"$WORKDIR/buildenv/bin/twine" check --strict "$WORKDIR"/dist/*
WHEEL="$(ls "$WORKDIR"/dist/*.whl)"
SDIST="$(ls "$WORKDIR"/dist/*.tar.gz)"
echo "wheel  : $(basename "$WHEEL")"
echo "sha256 : $(sha256sum "$WHEEL" | cut -d' ' -f1)"

# --- 3. Clean environment: wheel only, no editable install -------------------

echo
echo "=== Clean environment ==="
python3 -m venv "$WORKDIR/venv"
VENV_PY="$WORKDIR/venv/bin/python"
"$WORKDIR/venv/bin/pip" install --quiet --upgrade pip
"$WORKDIR/venv/bin/pip" install --quiet "$WHEEL" pytest pytest-cov hypothesis

RESOLVED="$("$VENV_PY" -c 'import encryption_helper; print(encryption_helper.__file__)')"
echo "import resolves to: $RESOLVED"

case "$RESOLVED" in
  "$WORKDIR"/venv/*site-packages/*) echo "OK: package under test is the installed wheel." ;;
  *)
    echo "ERROR: package resolved outside the clean venv." >&2
    echo "       This is the editable-install failure mode. Aborting." >&2
    exit 1
    ;;
esac

if "$WORKDIR/venv/bin/pip" list --editable 2>/dev/null | grep -qi encryption; then
  echo "ERROR: an editable install is present in the verification venv." >&2
  exit 1
fi

INSTALLED_VERSION="$("$VENV_PY" -c 'import encryption_helper; print(encryption_helper.__version__)')"
echo "version: $INSTALLED_VERSION"

# --- 4. Test the installed wheel --------------------------------------------

echo
echo "=== Test suite (against the installed wheel) ==="
# Tests run from outside the repository so the working tree cannot shadow the
# installed package on sys.path.
cp -r tests "$WORKDIR/tests"
cat > "$WORKDIR/pytest.ini" <<'INI'
[pytest]
addopts = --strict-markers --strict-config -ra
xfail_strict = true
filterwarnings = error
INI
(cd "$WORKDIR" && "$VENV_PY" -m pytest tests -q)

echo
echo "=== Doctests (against the installed wheel) ==="
SITE_PKG="$(dirname "$RESOLVED")"
(cd "$WORKDIR" && "$VENV_PY" -m pytest --doctest-modules "$SITE_PKG" -q)

# --- 5. Packaging invariants -------------------------------------------------

echo
echo "=== Packaging invariants ==="
"$VENV_PY" - "$WHEEL" <<'PY'
import sys, zipfile
names = zipfile.ZipFile(sys.argv[1]).namelist()
required = {
    "py.typed": lambda n: n.endswith("py.typed"),
    "LICENSE": lambda n: n.endswith("LICENSE"),
    "NOTICE": lambda n: n.endswith("NOTICE"),
}
missing = [label for label, test in required.items() if not any(map(test, names))]
if missing:
    sys.exit(f"ERROR: missing from wheel: {', '.join(missing)}")
print("wheel contains: py.typed, LICENSE, NOTICE")
PY

# --- 6. CLI smoke test, including an encrypted key ---------------------------

echo
echo "=== CLI smoke test ==="
EH="$WORKDIR/venv/bin/encryption-helper"
KEYS="$WORKDIR/keys"
"$EH" --version
"$EH" --quiet keygen --out-dir "$KEYS" --key-size 2048 --no-passphrase

MODE="$(stat -c '%a' "$KEYS/key.pem")"
[[ "$MODE" == "600" ]] || { echo "ERROR: private key is mode $MODE, expected 600" >&2; exit 1; }
echo "private key mode: $MODE"

export RC_PASS='release candidate passphrase'
"$EH" --quiet keygen --out-dir "$WORKDIR/enc" --key-size 2048 --passphrase-env RC_PASS
head -1 "$WORKDIR/enc/key.pem" | grep -q 'BEGIN ENCRYPTED PRIVATE KEY' \
  || { echo "ERROR: key was not encrypted at rest" >&2; exit 1; }
echo "encrypted key: OK"

echo "round trip" > "$WORKDIR/msg"
"$EH" --quiet encrypt --public-key "$KEYS/key.pub.pem" --in "$WORKDIR/msg" --out "$WORKDIR/msg.enc"
"$EH" --quiet decrypt --private-key "$KEYS/key.pem" --in "$WORKDIR/msg.enc" --out "$WORKDIR/msg.out"
diff -q "$WORKDIR/msg" "$WORKDIR/msg.out" >/dev/null \
  || { echo "ERROR: encrypt/decrypt round trip failed" >&2; exit 1; }
echo "encrypt/decrypt round trip: OK"

"$EH" --quiet sign --private-key "$WORKDIR/enc/key.pem" --passphrase-env RC_PASS \
  --in "$WORKDIR/msg" --out "$WORKDIR/msg.sig"
"$EH" verify --public-key "$WORKDIR/enc/key.pub.pem" \
  --signature "$WORKDIR/msg.sig" --in "$WORKDIR/msg" >/dev/null
echo "sign/verify with an encrypted key: OK"

# --- 7. Secret leakage check on the captured output --------------------------

echo
echo "=== Secret leakage check ==="
LEAK_LOG="$WORKDIR/leak.log"
"$EH" --log-level DEBUG keygen --out-dir "$WORKDIR/leak" --key-size 2048 \
  --passphrase-env RC_PASS >"$LEAK_LOG" 2>&1
if grep -q 'BEGIN .*PRIVATE KEY' "$LEAK_LOG"; then
  echo "ERROR: private key material appeared in command output." >&2
  exit 1
fi
if grep -qF "$RC_PASS" "$LEAK_LOG"; then
  echo "ERROR: passphrase appeared in command output." >&2
  exit 1
fi
echo "no key material or passphrase in DEBUG-level output"

# --- 8. Record ---------------------------------------------------------------

RECORD="build/release-candidate-$HEAD_SHORT.txt"
{
  echo "Release candidate verification"
  echo "generated : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "commit    : $HEAD_SHA"
  echo "branch    : $BRANCH"
  echo "tree      : $([[ -z "$DIRT" ]] && echo clean || echo DIRTY)"
  echo "version   : $INSTALLED_VERSION"
  echo "wheel     : $(basename "$WHEEL")"
  echo "wheel sha : $(sha256sum "$WHEEL" | cut -d' ' -f1)"
  echo "sdist sha : $(sha256sum "$SDIST" | cut -d' ' -f1)"
  echo "python    : $("$VENV_PY" -V)"
  echo "resolved  : installed wheel (no editable install)"
} > "$RECORD"

echo
echo "=== PASSED ==="
cat "$RECORD"
