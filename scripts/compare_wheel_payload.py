#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Prove that two commits ship byte-identical executable code.

Release audit tooling, not CI. It exists to turn a one-time manual comparison
into reproducible evidence a reviewer can run themselves.

The frozen v0.0.2 candidate and the post-release hardening branch build wheels
with *different* hashes, because ``readme = "README.md"`` embeds the README as
the PyPI long description and the README was corrected on the hardening
branch. That is a packaging-metadata difference, not a code difference -- but
"trust me, it is only metadata" is not evidence. This asserts it.

Each ref is built from a pristine ``git archive`` export, so an unclean working
tree cannot contaminate the comparison.

Usage:
    scripts/compare_wheel_payload.py feat/v0.0.2 chore/post-0.0.2-hardening
    scripts/compare_wheel_payload.py <ref-a> <ref-b> --prefix encryption_helper/
    scripts/compare_wheel_payload.py <ref-a> <ref-b> --json

Exit status:
    0  every member under the prefix is byte-identical
    1  the payload differs
    2  a build or usage failure
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import venv
import zipfile
from pathlib import Path

DEFAULT_PREFIX = "encryption_helper/"


def repository_root() -> Path:
    """Locate the repository from this script's own path, never from the CWD.

    Asking git "which repository am I standing in" answers a question about
    the shell, not about this tool. If the working directory has drifted -- a
    failure this project has hit more than once -- that answer is silently
    wrong, and a release audit that certifies the wrong checkout is worse than
    no audit at all.

    Returns:
        The absolute repository root.

    Raises:
        RuntimeError: If this script is not inside a checkout of this project.
    """
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
    if not script.is_relative_to(root):
        msg = f"{script} is outside the repository it resolved ({root})"
        raise RuntimeError(msg)

    pyproject = root / "pyproject.toml"
    if (
        not pyproject.is_file()
        or 'name = "encryption-helper"' not in pyproject.read_text(encoding="utf-8")
    ):
        msg = f"{root} is not the encryption-helper repository"
        raise RuntimeError(msg)
    return root


def report(
    payload_a: dict[str, str], payload_b: dict[str, str], outside: list[str]
) -> bool:
    """Print the comparison. Returns whether the payload is identical."""
    only_a = sorted(set(payload_a) - set(payload_b))
    only_b = sorted(set(payload_b) - set(payload_a))
    differing = sorted(
        n for n in set(payload_a) & set(payload_b) if payload_a[n] != payload_b[n]
    )
    identical = not (only_a or only_b or differing)

    if identical:
        print(f"PAYLOAD IDENTICAL: all {len(payload_a)} members match.")
    else:
        print("PAYLOAD DIFFERS:")
        for name in only_a:
            print(f"  only in A:  {name}")
        for name in only_b:
            print(f"  only in B:  {name}")
        for name in differing:
            print(f"  differs:    {name}")
            print(f"                A {payload_a[name]}")
            print(f"                B {payload_b[name]}")
    if outside:
        print()
        print("Outside the prefix (informational, not judged):")
        for name in outside:
            print(f"  differs:    {name}")
    return identical


def run(
    command: list[str], cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a command, raising with its output on failure."""
    result = subprocess.run(  # noqa: S603
        command, cwd=cwd, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout + result.stderr)
        msg = f"command failed: {' '.join(command)}"
        raise RuntimeError(msg)
    return result


def build_wheel(repo: Path, ref: str, workdir: Path, builder: Path) -> Path:
    """Export ``ref`` cleanly and build a wheel from it."""
    source = workdir / f"src-{ref.replace('/', '_')}"
    source.mkdir(parents=True)
    archive = subprocess.run(  # noqa: S603
        ["git", "-C", str(repo), "archive", "--format=tar", ref],  # noqa: S607
        capture_output=True,
        check=True,
    )
    subprocess.run(  # noqa: S603
        ["tar", "-x", "-C", str(source)],  # noqa: S607
        input=archive.stdout,
        check=True,
    )

    dist = workdir / f"dist-{ref.replace('/', '_')}"
    run([str(builder), "-m", "build", "--wheel", "--outdir", str(dist)], cwd=source)
    wheels = list(dist.glob("*.whl"))
    if len(wheels) != 1:
        msg = f"expected exactly one wheel for {ref}, got {len(wheels)}"
        raise RuntimeError(msg)
    return wheels[0]


def members(wheel: Path, prefix: str) -> dict[str, str]:
    """Map member name to SHA-256 for every member under ``prefix``."""
    with zipfile.ZipFile(wheel) as archive:
        return {
            name: hashlib.sha256(archive.read(name)).hexdigest()
            for name in archive.namelist()
            if name.startswith(prefix)
        }


def all_members(wheel: Path) -> dict[str, str]:
    """Map member name to SHA-256 for every member."""
    with zipfile.ZipFile(wheel) as archive:
        return {
            name: hashlib.sha256(archive.read(name)).hexdigest()
            for name in archive.namelist()
        }


def main(argv: list[str] | None = None) -> int:
    """Compare the payloads of two refs' wheels."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ref_a")
    parser.add_argument("ref_b")
    parser.add_argument("--prefix", default=DEFAULT_PREFIX)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args(argv)

    try:
        repo = repository_root()
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"repository: {repo}")
    (repo / "build").mkdir(exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="wheel-compare-", dir=repo / "build"))

    try:
        builder_env = workdir / "builder"
        venv.create(builder_env, with_pip=True)
        builder = builder_env / "bin" / "python"
        run([str(builder), "-m", "pip", "install", "--quiet", "build"])

        wheel_a = build_wheel(repo, args.ref_a, workdir, builder)
        wheel_b = build_wheel(repo, args.ref_b, workdir, builder)

        payload_a = members(wheel_a, args.prefix)
        payload_b = members(wheel_b, args.prefix)

        only_a = sorted(set(payload_a) - set(payload_b))
        only_b = sorted(set(payload_b) - set(payload_a))
        differing = sorted(
            name
            for name in set(payload_a) & set(payload_b)
            if payload_a[name] != payload_b[name]
        )
        identical = not (only_a or only_b or differing)

        # Everything outside the prefix, reported for context rather than
        # judged. A METADATA difference is expected when the README changes.
        outside = sorted(
            name
            for name in set(all_members(wheel_a)) & set(all_members(wheel_b))
            if not name.startswith(args.prefix)
            and all_members(wheel_a)[name] != all_members(wheel_b)[name]
        )

        report_data = {
            "ref_a": args.ref_a,
            "ref_b": args.ref_b,
            "sha_a": run(
                ["git", "-C", str(repo), "rev-parse", args.ref_a]
            ).stdout.strip(),
            "sha_b": run(
                ["git", "-C", str(repo), "rev-parse", args.ref_b]
            ).stdout.strip(),
            "prefix": args.prefix,
            "members_compared": len(payload_a),
            "payload_identical": identical,
            "only_in_a": only_a,
            "only_in_b": only_b,
            "differing": differing,
            "differing_outside_prefix": outside,
        }

        if args.as_json:
            print(json.dumps(report_data, indent=2))
            identical = report_data["payload_identical"]
        else:
            print(f"ref A: {args.ref_a}  ({report_data['sha_a']})")
            print(f"ref B: {args.ref_b}  ({report_data['sha_b']})")
            print(f"prefix: {args.prefix}")
            print(f"members compared: {len(payload_a)}")
            print()
            identical = report(payload_a, payload_b, outside)

        return 0 if identical else 1
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
