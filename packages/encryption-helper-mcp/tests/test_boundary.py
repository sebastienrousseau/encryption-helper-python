# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests for the boundary that makes this server safe to expose to a model.

The server's value rests on a claim: it answers questions and performs no
actions. A claim like that cannot be left to code review, because the way it
breaks is someone adding one convenient import. These tests assert it
structurally, by inspecting what the modules can reach.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from encryption_helper import encode_private_key, encode_public_key, generate

from encryption_helper_mcp import _tools
from encryption_helper_mcp._tools import ToolError, call, descriptors

PACKAGE = Path(_tools.__file__).parent

#: Names that act on, rather than report on, key material. None of them may
#: be reachable from this server.
FORBIDDEN = frozenset(
    {
        "generate",
        "generate_rsa",
        "generate_ed25519",
        "generate_ed448",
        "generate_ecdsa",
        "generate_x25519",
        "generate_mlkem",
        "generate_mldsa",
        "write_key_pair",
        "encrypt",
        "decrypt",
        "encrypt_stream",
        "decrypt_stream",
        "sign",
        "load_private_key",
        "load_private_key_file",
        "encode_private_key",
        "secure_write_bytes",
    }
)


def _imported_names(path: Path) -> set[str]:
    """Return every name a module brings into scope by import."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.ImportFrom, ast.Import)):
            names.update(alias.asname or alias.name for alias in node.names)
    return names


class TestTheServerCannotAct:
    @pytest.mark.parametrize("module", sorted(p.name for p in PACKAGE.glob("*.py")))
    def test_no_module_imports_anything_that_acts(self, module):
        """A convenient import is how this boundary would be lost."""
        offending = _imported_names(PACKAGE / module) & FORBIDDEN
        assert not offending, (
            f"{module} imports {sorted(offending)}, which act on key material. "
            "This server is read-only; expose operations through the CLI."
        )

    def test_no_module_writes_to_the_filesystem(self):
        """Opening a file for writing would break the read-only claim."""
        for path in PACKAGE.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and _is_open_call(node):
                    modes = [
                        arg.value
                        for arg in [*node.args[1:], *(kw.value for kw in node.keywords)]
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                    ]
                    for mode in modes:
                        assert "w" not in mode, (
                            f"{path.name} opens a file for writing: {mode!r}"
                        )
                        assert "a" not in mode, (
                            f"{path.name} opens a file for appending: {mode!r}"
                        )

    def test_no_tool_mentions_a_passphrase_argument(self):
        """Accepting a passphrase would put a secret into the model's context."""
        for descriptor in descriptors():
            properties = descriptor["inputSchema"].get("properties", {})
            assert "passphrase" not in properties
            assert "password" not in properties


def _is_open_call(node: ast.Call) -> bool:
    """Whether a call node is ``open(...)`` or ``something.open(...)``."""
    if isinstance(node.func, ast.Name):
        return node.func.id == "open"
    return isinstance(node.func, ast.Attribute) and node.func.attr == "open"


class TestPathConfinement:
    """A model must not be able to widen the server's reach by asking."""

    def test_a_path_outside_the_root_is_refused(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        with pytest.raises(ToolError, match="outside the permitted root"):
            call(root.resolve(), "scan_directory", {"path": str(outside)})

    def test_a_parent_traversal_is_refused(self, tmp_path):
        root = tmp_path / "root"
        root.mkdir()
        with pytest.raises(ToolError, match="outside the permitted root"):
            call(root.resolve(), "scan_directory", {"path": "../.."})

    def test_a_symlink_pointing_out_of_the_root_is_refused(self, tmp_path):
        """Resolution happens before the check, so the link cannot smuggle.

        Checking the unresolved path would have admitted this.
        """
        root = tmp_path / "root"
        root.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "elsewhere.pub").write_bytes(
            encode_public_key(generate("ed25519").public_key())
        )
        (root / "escape").symlink_to(outside)

        with pytest.raises(ToolError, match="outside the permitted root"):
            call(root.resolve(), "scan_directory", {"path": "escape"})

    def test_the_root_itself_is_permitted(self, tmp_path):
        root = tmp_path.resolve()
        result = call(root, "scan_directory", {"path": "."})
        assert result["root"] == str(root)

    def test_a_path_inside_the_root_is_permitted(self, tmp_path):
        nested = tmp_path / "keys"
        nested.mkdir()
        (nested / "k.pub").write_bytes(
            encode_public_key(generate("mlkem").public_key())
        )
        result = call(tmp_path.resolve(), "scan_directory", {"path": "keys"})
        assert result["summary"]["examined"] == 1

    def test_a_missing_path_is_a_clean_error(self, tmp_path):
        with pytest.raises(ToolError, match=r"cannot be read|No such file"):
            call(tmp_path.resolve(), "inspect_container", {"path": "absent.enc"})

    def test_an_empty_path_is_refused(self, tmp_path):
        with pytest.raises(ToolError, match="A path is required"):
            call(tmp_path.resolve(), "inspect_container", {"path": ""})

    def test_the_refusal_explains_how_to_widen_the_root(self, tmp_path):
        """A dead-end refusal wastes a turn; this one says what to change."""
        root = tmp_path / "root"
        root.mkdir()
        with pytest.raises(ToolError) as excinfo:
            call(root.resolve(), "scan_directory", {"path": "/"})
        assert "--root" in str(excinfo.value)


class TestNoSecretsLeave:
    def test_a_private_key_in_the_root_is_never_quoted(self, tmp_path):
        """A scan reports that a key exists, not what it contains."""
        key = generate("rsa", key_size=2048)
        pem = encode_private_key(key, passphrase=None)
        (tmp_path / "service.pem").write_bytes(pem)

        import json

        rendered = json.dumps(call(tmp_path.resolve(), "scan_directory", {"path": "."}))
        assert "BEGIN" not in rendered
        for line in pem.decode().splitlines()[1:-1]:
            if len(line) > 20:
                assert line not in rendered

    def test_fingerprinting_refuses_a_private_key_file(self, tmp_path):
        """The tool is for public keys; a private key must not load here."""
        key = generate("rsa", key_size=2048)
        path = tmp_path / "service.pem"
        path.write_bytes(encode_private_key(key, passphrase=None))
        with pytest.raises(ToolError):
            call(tmp_path.resolve(), "fingerprint_public_key", {"path": str(path)})

    def test_inspecting_a_container_reveals_no_plaintext(self, tmp_path):
        from encryption_helper import encrypt

        key = generate("mlkem")
        path = tmp_path / "data.enc"
        path.write_bytes(encrypt(key.public_key(), b"a-distinctive-plaintext"))
        result = call(tmp_path.resolve(), "inspect_container", {"path": "data.enc"})
        assert "a-distinctive-plaintext" not in str(result)
        assert result["key_establishment"] == "ml-kem-768"
