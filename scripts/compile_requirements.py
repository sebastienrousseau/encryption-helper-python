# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Regenerate the hash-locked requirement files in ``requirements/``.

Three files, each installed with ``pip --require-hashes``:

``runtime.txt``
    The package's runtime dependencies, for the container image. Compiled
    from the bounds in ``pyproject.toml`` and *constrained to the versions in
    poetry.lock*, so the image runs exactly what CI tested.
    ``tests/test_requirements_files.py`` fails if the two drift apart.
``build-backend.txt``
    poetry-core, so the container builds the wheel with
    ``--no-build-isolation`` instead of fetching the backend unpinned.
``release.txt``
    build, twine and cyclonedx-bom for the release and CI build jobs.
``audit.txt``
    bandit and pip-audit for the CI security job.
``ci.txt``
    pytest, coverage, hypothesis, ruff and mypy for the CI test, lint and
    type-check jobs, constrained to poetry.lock. Compiled with ``uv`` rather
    than pip-compile because it must be *universal*: the test matrix installs
    it on Python 3.10 to 3.14 across Linux, macOS and Windows, and a lock
    resolved for one interpreter omits what another needs (``tomli`` and
    ``exceptiongroup`` below 3.11, ``colorama`` on Windows).

Paths are passed relative to the repository root, and the poetry.lock
constraints are written to a fixed name rather than a random temporary file,
because pip-compile copies both into the generated ``# via`` comments. A
machine-specific path there makes every regeneration a spurious diff.

Run with pip-tools and uv installed, under Python 3.14 (the release jobs' version)::

    python scripts/compile_requirements.py

Run it after poetry.lock changes, and after editing a ``.in`` file.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS = ROOT / "requirements"
COMMON = ["--generate-hashes", "--allow-unsafe", "--strip-extras", "--quiet"]

RUNTIME_HEADER = """\
# Runtime dependencies of encryption-helper, with hashes, for the container
# build. Compiled from the bounds in pyproject.toml and constrained to the
# versions in poetry.lock; tests/test_requirements_files.py enforces that.
#
# Regenerate with: python scripts/compile_requirements.py
"""


def locked_versions() -> dict[str, str]:
    """Return every package version pinned in poetry.lock."""
    lock = tomllib.loads((ROOT / "poetry.lock").read_text(encoding="utf-8"))
    return {package["name"]: package["version"] for package in lock["package"]}


def compile_file(*args: str) -> None:
    """Run pip-compile, failing loudly."""
    subprocess.run(  # noqa: S603
        [sys.executable, "-m", "piptools", "compile", *COMMON, *args],
        cwd=ROOT,
        check=True,
    )


def compile_universal(stem: str, constraints: Path) -> None:
    """Compile ``stem``.in for every supported Python and platform, with uv."""
    subprocess.run(  # noqa: S603
        [
            sys.executable,
            "-m",
            "uv",
            "pip",
            "compile",
            "--universal",
            "--python-version",
            "3.10",
            "--generate-hashes",
            "--quiet",
            "--custom-compile-command",
            "python scripts/compile_requirements.py",
            "-c",
            constraints.relative_to(ROOT).as_posix(),
            "-o",
            f"requirements/{stem}.txt",
            f"requirements/{stem}.in",
        ],
        cwd=ROOT,
        check=True,
    )


def main() -> None:
    """Compile every requirements file."""
    constraints = REQUIREMENTS / ".poetry-lock-constraints.txt"
    constraints.write_text(
        "".join(f"{n}=={v}\n" for n, v in sorted(locked_versions().items())),
        encoding="utf-8",
    )
    try:
        output = REQUIREMENTS / "runtime.txt"
        compile_file(
            "--no-header",
            "-c",
            constraints.relative_to(ROOT).as_posix(),
            "-o",
            output.relative_to(ROOT).as_posix(),
            "pyproject.toml",
        )
        output.write_text(RUNTIME_HEADER + output.read_text(encoding="utf-8"))
        compile_universal("ci", constraints)
    finally:
        constraints.unlink()
    for name in ("build-backend", "release", "audit"):
        compile_file(
            "-o",
            f"requirements/{name}.txt",
            f"requirements/{name}.in",
        )


if __name__ == "__main__":
    main()
