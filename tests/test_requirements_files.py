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


def test_ci_tool_pins_equal_poetry_lock():
    """CI must run the linters and test tools a developer's lock gives them.

    The CI jobs used to ``pip install pytest ruff mypy`` unpinned, so an
    upstream release could change a verdict between a local run and CI.
    """
    lock = {
        p["name"].lower(): p["version"]
        for p in tomllib.loads((ROOT / "poetry.lock").read_text(encoding="utf-8"))[
            "package"
        ]
    }
    drift = {
        name: (version, lock.get(name))
        for name, version in _pins("ci.txt").items()
        if lock.get(name) != version
    }
    assert not drift, f"ci.txt differs from poetry.lock: {drift}. {REGENERATE}"


def test_ci_installs_its_tools_from_hashes():
    """No CI job may install a test, lint or type-check tool unpinned."""
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "pip install --require-hashes -r requirements/ci.txt" in ci
    unpinned = re.findall(
        r"(?m)^(?!\s*#).*pip install[^\n]*"
        r"\b(pytest|hypothesis|ruff|mypy|poetry|tomli)\b",
        ci,
    )
    assert not unpinned, f"unpinned CI tools: {sorted(set(unpinned))}"


def test_runtime_covers_every_declared_dependency():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = {
        re.split(r"[<>=!~; \[]", d)[0].lower()
        for d in project["project"]["dependencies"]
    }
    assert declared <= set(_pins("runtime.txt")), REGENERATE


@pytest.mark.parametrize(
    "name", ["runtime.txt", "build-backend.txt", "release.txt", "audit.txt", "ci.txt"]
)
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


_COMPILED_FROM_IN = ["build-backend", "release", "audit", "ci"]


def _top_level(stem: str) -> set[str]:
    """Package names an ``.in`` file asks for, extras and bounds removed."""
    text = (REQUIREMENTS / f"{stem}.in").read_text(encoding="utf-8")
    lines = (line.strip() for line in text.splitlines())
    return {
        re.split(r"[\[<>=!~ ;]", line, maxsplit=1)[0].lower()
        for line in lines
        if line and not line.startswith("#")
    }


@pytest.mark.parametrize("stem", _COMPILED_FROM_IN)
def test_every_in_file_names_what_its_lock_pins(stem):
    """An ``.in`` file once held only its comment header.

    The committed ``.txt`` still had every pin, so nothing failed -- until
    the next regeneration, which would have produced an empty lock and a
    release job that installs nothing.
    """
    wanted = _top_level(stem)
    assert wanted, f"requirements/{stem}.in names no packages. {REGENERATE}"
    missing = wanted - set(_pins(f"{stem}.txt"))
    assert not missing, f"{stem}.txt does not pin {sorted(missing)}. {REGENERATE}"


@pytest.mark.parametrize(
    "name", ["runtime.txt", "build-backend.txt", "release.txt", "audit.txt", "ci.txt"]
)
def test_lock_files_carry_no_machine_specific_paths(name):
    """pip-compile copies its arguments into comments; keep them relative."""
    text = (REQUIREMENTS / name).read_text(encoding="utf-8")
    assert not re.search(r"(?m)(^|\s)(/|[A-Za-z]:\\)\S*requirements", text)
    # A pip-compile constraint passed as a random temporary file.
    assert not re.search(r"-c \S*tmp\w+\.txt", text)


def test_ci_audits_the_pinned_sets_with_pinned_scanners():
    """A bare ``pip-audit`` audits the job's own environment, not the project."""
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "pip install --require-hashes -r requirements/audit.txt" in ci
    assert '-r "requirements/${set}.txt"' in ci
    assert "for set in runtime build-backend release audit" in ci
    assert not re.search(r"pip install[^\n]*\bpip-audit\b", ci)
