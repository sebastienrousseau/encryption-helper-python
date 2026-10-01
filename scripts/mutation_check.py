#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Deterministic mutation testing for the security-critical code paths.

A test suite that passes proves the code does what the tests say. It does not
prove the tests would notice if the code stopped doing it. This harness
answers the second question: it breaks a security property on purpose and
checks that some test fails.

Why not `mutmut`
----------------

A full mutation run over 1,240 statements against 674 tests takes hours, and
a gate nobody runs is not a gate. `mutmut` also conflicts with this project's
pytest configuration (`--doctest-modules` in `addopts`).

This harness trades exhaustiveness for being fast enough to run on every
change. Each mutation is a hand-picked semantic break -- a permission
widened, a check deleted, a nonce made constant -- paired with the smallest
test selection that should catch it. It runs in a couple of minutes and the
report names the property, not a line number.

A surviving mutation is a real finding: it means a security property is
asserted nowhere.

Usage:
    scripts/mutation_check.py              # all mutations
    scripts/mutation_check.py --list      # show them without running
    scripts/mutation_check.py --filter io # only matching ids
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Mutation:
    """One deliberate break, and the tests that must notice it.

    Attributes:
        id: Short stable identifier.
        property: The security property being removed, in plain words.
        path: File to patch, relative to the repository root.
        old: Exact source to replace. Must appear exactly once.
        new: Replacement source.
        tests: Pytest selection expected to fail.
    """

    id: str
    property: str
    path: str
    old: str
    new: str
    tests: tuple[str, ...]


MUTATIONS: tuple[Mutation, ...] = (
    # --- filesystem guarantees -------------------------------------------
    Mutation(
        id="io-mode",
        property="private keys are written owner-only, not at the umask default",
        path="encryption_helper/_io.py",
        old="SECRET_FILE_MODE = 0o600",
        new="SECRET_FILE_MODE = 0o644",
        tests=(
            "tests/test_io.py",
            "tests/keys/test_store.py",
            "tests/test_cli.py",
            "tests/test_security_regressions.py",
        ),
    ),
    Mutation(
        id="io-symlink",
        property="a symlinked destination is refused",
        path="encryption_helper/_io.py",
        old="    if path.is_symlink():",
        new="    if False:",
        tests=("tests/test_io.py", "tests/test_release_candidate.py"),
    ),
    Mutation(
        id="io-restore",
        property="a write that fails after displacing a file restores it",
        path="encryption_helper/_io.py",
        # One rollback site now, reached by every failing write stage.
        old="        if displaced is not None:\n            displaced.restore()",
        new="        if displaced is not None:\n            pass",
        tests=("tests/test_io.py", "tests/test_release_candidate.py"),
    ),
    Mutation(
        id="io-exclusive",
        property="an existing destination is not silently replaced",
        path="encryption_helper/_io.py",
        old="    if not overwrite:",
        new="    if False:",
        tests=("tests/test_io.py", "tests/keys/test_store.py"),
    ),
    # --- pair transaction -------------------------------------------------
    Mutation(
        id="store-rollback",
        property="a half-written key pair is rolled back",
        path="encryption_helper/keys/store.py",
        old="        _undo(private_outcome)\n        raise",
        new="        raise",
        tests=("tests/test_release_candidate.py", "tests/test_security_regressions.py"),
    ),
    Mutation(
        id="store-validate",
        property="a mismatched key pair never reaches the disk",
        path="encryption_helper/keys/store.py",
        old="    _validate_pair(key, private_bytes, public_bytes, passphrase, fmt)",
        new="    pass",
        tests=("tests/keys/test_store.py",),
    ),
    Mutation(
        id="store-alias",
        property="a multiply-linked private key destination is refused",
        path="encryption_helper/keys/store.py",
        old="    _reject_aliased_private_key(private_path)",
        new="    pass",
        tests=("tests/test_release_candidate.py",),
    ),
    # --- envelope ---------------------------------------------------------
    Mutation(
        id="envelope-kdf-binding",
        property="the KEM identifier is bound into the derived content key",
        path="encryption_helper/crypto/envelope.py",
        old="        info=_HKDF_INFO + bytes([kem_id]),",
        new="        info=_HKDF_INFO,",
        tests=("tests/crypto/test_defence_in_depth.py",),
    ),
    Mutation(
        id="envelope-magic",
        property="a container with the wrong magic is rejected",
        path="encryption_helper/crypto/envelope.py",
        old="    if magic != MAGIC:",
        new="    if False:",
        tests=("tests/crypto/test_envelope.py",),
    ),
    Mutation(
        id="envelope-version",
        property="an unsupported container version is rejected",
        path="encryption_helper/crypto/envelope.py",
        old="    if version != VERSION:",
        new="    if False:",
        tests=("tests/crypto/test_envelope.py",),
    ),
    Mutation(
        id="envelope-aad",
        property="the framing is authenticated as associated data",
        path="encryption_helper/crypto/envelope.py",
        old="    return header + encapsulation + nonce + extra",
        new="    return extra",
        tests=("tests/crypto/test_defence_in_depth.py",),
    ),
    Mutation(
        id="envelope-keylen",
        property="a recovered content key of the wrong length is rejected",
        path="encryption_helper/crypto/envelope.py",
        old="    if len(content_key) != _CONTENT_KEY_SIZE:",
        new="    if False:",
        tests=("tests/crypto/test_envelope.py",),
    ),
    # --- streaming --------------------------------------------------------
    Mutation(
        id="stream-final-flag",
        property="truncation is detected (the last segment is marked final)",
        path="encryption_helper/crypto/streaming.py",
        old='    return (\n        prefix + number.to_bytes(_COUNTER_SIZE, "big") + (b"\\x01" if final else b"\\x00")',
        new='    return prefix + number.to_bytes(_COUNTER_SIZE, "big") + b"\\x00"',
        tests=("tests/crypto/test_streaming.py",),
    ),
    Mutation(
        id="stream-counter",
        property="segment reordering and dropping are detected",
        path="encryption_helper/crypto/streaming.py",
        old='    return (\n        prefix + number.to_bytes(_COUNTER_SIZE, "big") + (b"\\x01" if final else b"\\x00")',
        new='    return prefix + bytes(_COUNTER_SIZE) + (b"\\x01" if final else b"\\x00")',
        tests=("tests/crypto/test_streaming.py",),
    ),
    Mutation(
        id="stream-prefix",
        property="the per-stream nonce prefix is random, not fixed",
        path="encryption_helper/crypto/streaming.py",
        old="    prefix = os.urandom(_PREFIX_SIZE)",
        new="    prefix = bytes(_PREFIX_SIZE)",
        tests=("tests/crypto/test_defence_in_depth.py",),
    ),
    Mutation(
        id="stream-segment-bounds",
        property="an out-of-range segment size is refused",
        path="encryption_helper/crypto/streaming.py",
        old="    if not MIN_SEGMENT_SIZE <= segment_size <= MAX_SEGMENT_SIZE:",
        new="    if False:",
        tests=("tests/crypto/test_streaming.py",),
    ),
    # --- signing ----------------------------------------------------------
    Mutation(
        id="sign-verify-raises",
        property="verify() fails closed rather than returning quietly",
        path="encryption_helper/crypto/signing.py",
        old="        raise SignatureVerificationError(msg) from exc",
        new="        return",
        tests=("tests/crypto/test_signing.py",),
    ),
    # --- passphrase policy ------------------------------------------------
    Mutation(
        id="cli-plaintext-consent",
        property="an unencrypted private key requires explicit consent",
        path="encryption_helper/cli.py",
        old="    if args.no_passphrase:\n        return None",
        new="    if True:\n        return None",
        tests=("tests/test_security_regressions.py",),
    ),
    Mutation(
        id="cli-env-whitespace",
        property="a whitespace-only passphrase is rejected",
        path="encryption_helper/cli.py",
        old="        if not value.strip():",
        new="        if False:",
        tests=("tests/test_release_candidate.py",),
    ),
    Mutation(
        id="cli-newline-semantics",
        property="exactly one trailing newline is stripped from a passphrase file",
        path="encryption_helper/cli.py",
        old='    if data.endswith(b"\\r\\n"):\n        return data[:-2]\n    if data.endswith(b"\\n"):\n        return data[:-1]\n    return data',
        new="    return data.strip()",
        tests=("tests/test_release_candidate.py",),
    ),
)


def repository_root() -> Path:
    """Locate the repository from this script's path, never the CWD."""
    script = Path(__file__).resolve()
    probe = subprocess.run(  # noqa: S603
        ["git", "-C", str(script.parent), "rev-parse", "--show-toplevel"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        msg = f"{script} is not inside a git repository"
        raise RuntimeError(msg)
    root = Path(probe.stdout.strip()).resolve()
    pyproject = root / "pyproject.toml"
    if (
        not pyproject.is_file()
        or 'name = "encryption-helper"' not in pyproject.read_text(encoding="utf-8")
    ):
        msg = f"{root} is not the encryption-helper repository"
        raise RuntimeError(msg)
    return root


def apply(root: Path, mutation: Mutation) -> str:
    """Patch the file and return the original text.

    Raises:
        RuntimeError: If the target text is absent or ambiguous, which means
            the mutation has gone stale and must be updated rather than
            silently skipped.
    """
    path = root / mutation.path
    original = path.read_text(encoding="utf-8")
    occurrences = original.count(mutation.old)
    if occurrences != 1:
        msg = (
            f"{mutation.id}: target text appears {occurrences} times in "
            f"{mutation.path}, expected exactly 1. The mutation is stale."
        )
        raise RuntimeError(msg)
    path.write_text(original.replace(mutation.old, mutation.new), encoding="utf-8")
    return original


def _pytest(root: Path, selection: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    """Run pytest over ``selection`` and return the completed process."""
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "pytest",
            "-x",
            "-q",
            "--no-header",
            "-p",
            "no:cacheprovider",
            "--no-cov",
            *selection,
        ],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )


def verify_baseline(root: Path, mutations: list[Mutation]) -> str | None:
    """Confirm the unmutated tests actually pass before trusting a failure.

    Without this, *any* reason pytest exits non-zero reads as "mutation
    caught" -- a missing pytest, a bad argument, an unrelated pre-existing
    failure. The first version of this harness reported 20/20 in under a
    second because `sys.executable` under the shebang was the system
    interpreter, which has no pytest. Every mutation "passed" because
    nothing ran.

    Returns:
        An error description, or None if the baseline is sound.
    """
    selection = tuple(sorted({path for m in mutations for path in m.tests}))
    result = _pytest(root, selection)
    if result.returncode != 0:
        tail = (result.stdout + result.stderr).strip().splitlines()[-6:]
        return (
            "the test selection does not pass on unmutated code, so a "
            "failure cannot be attributed to a mutation:\n    " + "\n    ".join(tail)
        )
    return None


def run_tests(root: Path, mutation: Mutation) -> bool:
    """Run the mutation's test selection. True if something failed."""
    return _pytest(root, mutation.tests).returncode != 0


def preflight(root: Path, selected: list[Mutation]) -> int:
    """Refuse to run unless the tree is clean and the baseline passes.

    Returns:
        0 to proceed, or a non-zero exit code.
    """
    dirt = subprocess.run(  # noqa: S603
        ["git", "-C", str(root), "status", "--porcelain"],  # noqa: S607
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    if dirt.strip():
        print(
            "error: working tree is not clean; refusing to patch files.",
            file=sys.stderr,
        )
        print(dirt, file=sys.stderr)
        return 2

    print("verifying the baseline passes ... ", end="", flush=True)
    problem = verify_baseline(root, selected)
    if problem is not None:
        print("FAILED")
        print(f"error: {problem}", file=sys.stderr)
        print(
            "\nhint: use the interpreter that has pytest, e.g.\n"
            "  .venv/bin/python scripts/mutation_check.py",
            file=sys.stderr,
        )
        return 2
    print("ok")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Apply each mutation and confirm the suite notices."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="Show mutations only.")
    parser.add_argument("--filter", metavar="TEXT", help="Only ids containing TEXT.")
    args = parser.parse_args(argv)

    try:
        root = repository_root()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    selected = [m for m in MUTATIONS if not args.filter or args.filter in m.id]
    if not selected:
        print(f"no mutation matches {args.filter!r}", file=sys.stderr)
        return 2

    if args.list:
        for m in selected:
            print(f"  {m.id:24} {m.property}")
        return 0

    status = preflight(root, selected)
    if status:
        return status

    print(f"\n{len(selected)} mutations\n")
    survivors: list[Mutation] = []
    started = time.perf_counter()

    for index, mutation in enumerate(selected, start=1):
        print(f"[{index}/{len(selected)}] {mutation.id:24} ", end="", flush=True)
        try:
            original = apply(root, mutation)
        except RuntimeError as exc:
            print("STALE")
            print(f"    {exc}", file=sys.stderr)
            return 2
        try:
            caught = run_tests(root, mutation)
        finally:
            (root / mutation.path).write_text(original, encoding="utf-8")

        if caught:
            print("caught")
        else:
            print("SURVIVED")
            print(f"    unasserted property: {mutation.property}")
            survivors.append(mutation)

    elapsed = time.perf_counter() - started
    score = (len(selected) - len(survivors)) / len(selected) * 100
    print(
        f"\n{score:.0f}% caught ({len(selected) - len(survivors)}/{len(selected)}) in {elapsed:.0f}s"
    )

    if survivors:
        print("\nSurviving mutations mean these properties are asserted nowhere:")
        for m in survivors:
            print(f"  {m.id}: {m.property}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
