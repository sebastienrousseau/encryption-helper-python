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

Run with pip-tools installed, under Python 3.14 (the release jobs' version)::

    python scripts/compile_requirements.py

Run it after poetry.lock changes, and after editing a ``.in`` file.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
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


def main() -> None:
    """Compile all three files."""
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as handle:
        handle.writelines(f"{n}=={v}\n" for n, v in sorted(locked_versions().items()))
        constraints = handle.name
    try:
        output = REQUIREMENTS / "runtime.txt"
        compile_file(
            "--no-header", "-c", constraints, "-o", str(output), "pyproject.toml"
        )
        output.write_text(RUNTIME_HEADER + output.read_text(encoding="utf-8"))
    finally:
        Path(constraints).unlink()
    for name in ("build-backend", "release"):
        compile_file(
            "-o", str(REQUIREMENTS / f"{name}.txt"), str(REQUIREMENTS / f"{name}.in")
        )


if __name__ == "__main__":
    main()
