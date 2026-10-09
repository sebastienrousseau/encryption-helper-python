# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests for package-level metadata and the public API surface."""

from __future__ import annotations

import importlib
import logging
import re
import subprocess
import sys
from importlib import metadata
from pathlib import Path

import encryption_helper
import pytest
from encryption_helper.errors import EncryptionHelperError

from ._support import source_tree_only


class TestVersion:
    def test_version_matches_installed_metadata(self):
        """Regression test for finding M1.

        The version used to be written out in three separate files plus a
        test, so they could -- and did -- drift. There is now one source.
        """
        assert encryption_helper.__version__ == metadata.version("encryption-helper")

    @source_tree_only
    def test_no_python_source_hard_codes_the_version(self):
        """Regression test for finding M1.

        ``0.0.1`` was declared in ``__init__.py``, ``pyproject.toml`` and
        ``setup.py``, and asserted by a fourth file. Bumping it meant four
        edits, so it drifted. Every package now resolves its version from
        installed metadata, so only a ``pyproject.toml`` may name one.
        """
        version = metadata.version("encryption-helper")
        # A quoted literal is what a declaration looks like. A bare mention,
        # such as the branch name ``feat/v0.0.2`` in release tooling, is not.
        literal = "[\"']" + re.escape(version) + "[\"']"
        found = subprocess.run(  # noqa: S603
            ["git", "grep", "-lE", literal, "--", "*.py"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert found.stdout.split() == []

    @source_tree_only
    def test_every_distribution_declares_the_same_version(self):
        """The companion packages are released together, so they move together.

        Independent versioning would be defensible, but it is not what
        happens here: `packages/*` are built and tagged with the core. A
        divergence would therefore be an oversight, not a decision.
        """
        version = metadata.version("encryption-helper")
        declared = subprocess.run(
            ["git", "grep", "-l", "-E", r'^version = "', "--", "*pyproject.toml"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.split()
        assert declared, "no pyproject declares a version"
        for path in declared:
            text = Path(path).read_text(encoding="utf-8")
            match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
            assert match is not None, path
            assert match.group(1) == version, f"{path} declares {match.group(1)}"

    def test_version_is_importable(self):
        assert isinstance(encryption_helper.__version__, str)


class TestPublicAPI:
    @pytest.mark.parametrize("name", encryption_helper.__all__)
    def test_everything_exported_exists(self, name):
        assert hasattr(encryption_helper, name)

    def test_all_has_no_duplicates(self):
        """Ordering is ruff's job (RUF022, isort-style: constants, then
        classes, then functions). Asserting plain `sorted()` here contradicted
        it, so this checks the property ruff does not: no duplicates."""
        assert len(encryption_helper.__all__) == len(set(encryption_helper.__all__))

    def test_all_covers_every_public_name(self):
        """Nothing public is missing from __all__."""
        public = {
            name
            for name in vars(encryption_helper)
            if not name.startswith("_") and name != "annotations"
        }
        # Submodules are reachable but are not part of the curated surface.
        public -= {
            "cli",
            "crypto",
            "errors",
            "inventory",
            "keys",
            "logging",
            "metadata",
            "policy",
        }
        assert public <= set(encryption_helper.__all__), sorted(
            public - set(encryption_helper.__all__)
        )

    def test_no_legacy_names_survive(self):
        """The removed API must be gone, not quietly still importable."""
        for removed in ("Context", "generate_rsa_key", "main"):
            assert not hasattr(encryption_helper, removed)

    @pytest.mark.parametrize(
        "module",
        [
            "encryption_helper.context",
            "encryption_helper.common.strings",
            "encryption_helper.utils.io.write_file",
            "encryption_helper.utils.checks.checks",
        ],
    )
    def test_dead_modules_are_removed(self, module):
        """Findings H2 and C5: the unused, broken IO layer is gone."""
        with pytest.raises(ModuleNotFoundError):
            importlib.import_module(module)

    def test_every_error_derives_from_the_base(self):
        from encryption_helper import errors

        for name in errors.__all__:
            if name == "EncryptionHelperError":
                continue
            assert issubclass(getattr(errors, name), EncryptionHelperError)


class TestLogging:
    def test_library_installs_only_a_null_handler(self):
        """A library must not configure logging on the host's behalf."""
        handlers = logging.getLogger("encryption_helper").handlers
        assert all(isinstance(h, logging.NullHandler) for h in handlers)

    def test_package_import_does_not_call_basic_config(self):
        """Importing must not attach a handler to the root logger."""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import logging, encryption_helper;"
                "print(len(logging.getLogger().handlers))",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == "0"


class TestTypeMarker:
    def test_py_typed_is_present(self):
        """Without this marker, downstream consumers get no type information."""
        from pathlib import Path

        assert (Path(encryption_helper.__file__).parent / "py.typed").is_file()


class TestModuleEntryPoint:
    """`python -m encryption_helper` executes the same code as the script.

    The subprocess tests prove this works end to end, but a subprocess is
    invisible to in-process coverage. `runpy` executes the module body --
    including the `if __name__ == "__main__"` guard -- in this interpreter.
    """

    def test_module_execution_dispatches_to_the_cli(self, monkeypatch, capsys):
        import runpy

        monkeypatch.setattr(sys, "argv", ["encryption-helper", "--version"])
        with pytest.raises(SystemExit) as excinfo:
            runpy.run_module("encryption_helper", run_name="__main__")

        assert excinfo.value.code == 0
        assert "encryption-helper" in capsys.readouterr().out

    def test_module_execution_propagates_the_exit_code(
        self, tmp_path, monkeypatch, capsys
    ):
        import runpy

        monkeypatch.setattr(
            sys,
            "argv",
            ["encryption-helper", "keygen", "--out-dir", str(tmp_path)],
        )
        monkeypatch.setattr(
            "encryption_helper.cli._passphrase._interactive", lambda: False
        )
        with pytest.raises(SystemExit) as excinfo:
            runpy.run_module("encryption_helper", run_name="__main__")

        # Refusing to write an unencrypted key without consent is exit 2.
        assert excinfo.value.code == 2
        assert "unencrypted" in capsys.readouterr().err
