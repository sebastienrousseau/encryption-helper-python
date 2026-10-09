# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""The hash-locked requirement files must stay true.

``requirements/runtime.txt`` is what the container image installs. If its
pins drifted from poetry.lock, the image would run dependency versions CI
never tested -- silently, because the hashes would still verify. The other
two files only need to be fully hashed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - 3.10 only
    import tomli as tomllib

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS = ROOT / "requirements"
PIN = re.compile(r"^([A-Za-z0-9_.-]+)==(\S+)", re.MULTILINE)
REGENERATE = "Run: python scripts/compile_requirements.py"


def _pins(name: str) -> dict[str, str]:
    text = (REQUIREMENTS / name).read_text(encoding="utf-8")
    return {pkg.lower(): version for pkg, version in PIN.findall(text)}


def test_runtime_pins_equal_poetry_lock():
    lock = tomllib.loads((ROOT / "poetry.lock").read_text(encoding="utf-8"))
    locked = {p["name"].lower(): p["version"] for p in lock["package"]}
    runtime = _pins("runtime.txt")
    assert "cryptography" in runtime
    drift = {n: (v, locked.get(n)) for n, v in runtime.items() if locked.get(n) != v}
    assert not drift, f"runtime.txt differs from poetry.lock: {drift}. {REGENERATE}"


def test_runtime_covers_every_declared_dependency():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = {
        re.split(r"[<>=!~; \[]", d)[0].lower()
        for d in project["project"]["dependencies"]
    }
    assert declared <= set(_pins("runtime.txt")), REGENERATE


@pytest.mark.parametrize("name", ["runtime.txt", "build-backend.txt", "release.txt"])
def test_every_pin_carries_a_hash(name):
    """`pip --require-hashes` refuses a file with an unhashed pin; fail here first."""
    text = (REQUIREMENTS / name).read_text(encoding="utf-8")
    entries = re.split(
        r"\n(?=[A-Za-z0-9])", text.split("\n", 1)[1] if text.startswith("#") else text
    )
    pinned = [e for e in entries if PIN.match(e)]
    assert pinned
    unhashed = [e.split()[0] for e in pinned if "--hash=sha256:" not in e]
    assert not unhashed, f"{name}: no hash for {unhashed}. {REGENERATE}"


def test_build_backend_satisfies_the_build_system():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    (requirement,) = project["build-system"]["requires"]
    assert requirement.startswith("poetry-core")
    assert "poetry-core" in _pins("build-backend.txt")
