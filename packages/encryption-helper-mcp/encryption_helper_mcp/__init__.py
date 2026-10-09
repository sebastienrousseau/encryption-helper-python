# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Read-only Model Context Protocol server for encryption-helper.

Exposes the assessment side of :mod:`encryption_helper` to an assistant:
which algorithms stop being acceptable and when, what protects a given
encrypted file, and what cryptographic material exists under a path.

It deliberately exposes nothing that acts. Key generation, encryption,
decryption and signing are absent by design, because routing private key
material through a model's context window would contradict the purpose of a
tool whose job is to keep that material on the operator's machine. The
command-line interface remains the way to perform those operations.
"""

from __future__ import annotations

import re
from pathlib import Path

__all__ = ["__version__"]

#: Matches the version in this distribution's ``pyproject.toml``.
_DECLARED = re.compile(r'^version\s*=\s*"([^"]+)"', re.MULTILINE)


def _resolve_version() -> str:
    """Return the distribution version.

    Read from installed metadata rather than hard-coded here, so
    ``pyproject.toml`` is the only place a version is declared and bumping it
    is one edit. Falls back to the declared value when running from a source
    checkout, where no metadata exists.
    """
    from importlib.metadata import PackageNotFoundError, version  # noqa: PLC0415

    try:
        return version("encryption-helper-mcp")
    except PackageNotFoundError:
        pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
        try:
            found = _DECLARED.search(pyproject.read_text(encoding="utf-8"))
        except OSError:  # pragma: no cover - only if the checkout is partial
            return "unknown"
        return found.group(1) if found else "unknown"


def __getattr__(name: str) -> object:
    """Resolve ``__version__`` on first access.

    Raises:
        AttributeError: For any other name, as normal.
    """
    if name == "__version__":
        resolved = _resolve_version()
        globals()["__version__"] = resolved
        return resolved
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
