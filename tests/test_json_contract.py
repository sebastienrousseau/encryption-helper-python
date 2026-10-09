# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests that the published JSON schema describes what the CLI actually emits.

``docs/schemas/cli-output-v1.json`` is a contract offered to anyone writing
automation against this tool. A schema that has drifted from the output is
worse than no schema, because it will be trusted.

These tests deliberately avoid a JSON Schema validation library. A validator
confirms that output satisfies the schema; the risk here is the opposite
direction -- that the schema promises a field the CLI no longer emits, which
a validator would not notice. Both directions are checked by comparing the
two sets of names.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from encryption_helper import encode_public_key, encrypt, generate
from encryption_helper.cli import JSON_SCHEMA_VERSION, main

from ._support import envelope, error_of, result_of

SCHEMA_PATH = Path(__file__).resolve().parents[1] / "docs" / "schemas"


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads((SCHEMA_PATH / "cli-output-v1.json").read_text())


def _run(argv: list[str], capsys) -> str:
    main(argv)
    captured = capsys.readouterr()
    # Errors and reports that would collide with binary output go to stderr.
    return captured.out if captured.out.strip().startswith("{") else captured.err


class TestSchemaMatchesTheConstant:
    def test_the_declared_version_matches_the_code(self, schema):
        assert schema["properties"]["schema_version"]["const"] == JSON_SCHEMA_VERSION

    def test_the_filename_states_the_version(self, schema):
        assert f"v{JSON_SCHEMA_VERSION}" in schema["$id"]

    def test_every_version_has_exactly_one_schema_file(self):
        """A second file for the same version would make the contract unclear."""
        published = sorted(p.name for p in SCHEMA_PATH.glob("cli-output-v*.json"))
        assert published == [f"cli-output-v{JSON_SCHEMA_VERSION}.json"]


class TestEveryCommandEmitsTheEnvelope:
    """The envelope is what lets a consumer branch without guessing."""

    def test_keygen(self, tmp_path, capsys):
        text = _run(
            ["--json", "-q", "keygen", "--out-dir", str(tmp_path), "--no-passphrase"],
            capsys,
        )
        document = envelope(text)
        assert document["command"] == "keygen"
        assert document["status"] == "ok"

    def test_capabilities(self, capsys):
        assert envelope(_run(["--json", "capabilities"], capsys))["command"] == (
            "capabilities"
        )

    def test_fingerprint(self, tmp_path, capsys):
        key = generate("ed25519")
        path = tmp_path / "k.pub"
        path.write_bytes(encode_public_key(key.public_key()))
        document = envelope(_run(["--json", "fingerprint", str(path)], capsys))
        assert document["command"] == "fingerprint"

    def test_inspect(self, tmp_path, capsys):
        key = generate("mlkem")
        path = tmp_path / "data.enc"
        path.write_bytes(encrypt(key.public_key(), b"payload"))
        document = envelope(_run(["--json", "inspect", "--in", str(path)], capsys))
        assert document["command"] == "inspect"

    def test_scan(self, tmp_path, capsys):
        document = envelope(_run(["--json", "scan", str(tmp_path)], capsys))
        assert document["command"] == "scan"

    def test_an_error_also_carries_the_envelope(self, tmp_path, capsys):
        """Automation needs a parseable failure, not just a non-zero exit."""
        text = _run(["--json", "fingerprint", str(tmp_path / "absent")], capsys)
        document = envelope(text)
        assert document["status"] == "error"
        assert document["command"] == "fingerprint"


class TestDeclaredFieldsAreEmitted:
    """Guards the direction a validator cannot: the schema over-promising."""

    def test_scan_emits_every_declared_summary_field(self, tmp_path, schema, capsys):
        key = generate("rsa", key_size=2048)
        (tmp_path / "legacy.pub").write_bytes(encode_public_key(key.public_key()))
        summary = result_of(_run(["--json", "scan", str(tmp_path)], capsys))["summary"]
        declared = schema["properties"]["result"]["properties"]["summary"]["required"]
        assert set(declared) <= set(summary)

    def test_scan_emits_every_declared_finding_field(self, tmp_path, schema, capsys):
        key = generate("rsa", key_size=2048)
        (tmp_path / "legacy.pub").write_bytes(encode_public_key(key.public_key()))
        findings = result_of(_run(["--json", "scan", str(tmp_path)], capsys))[
            "findings"
        ]
        declared = schema["properties"]["result"]["properties"]["findings"]["items"][
            "required"
        ]
        assert set(declared) <= set(findings[0])

    def test_scan_emits_every_declared_horizon_field(self, tmp_path, schema, capsys):
        horizon = result_of(_run(["--json", "scan", str(tmp_path)], capsys))["horizon"]
        declared = schema["properties"]["result"]["properties"]["horizon"]["required"]
        assert set(declared) <= set(horizon)

    def test_an_error_emits_every_declared_field(self, tmp_path, schema, capsys):
        error = error_of(_run(["--json", "fingerprint", str(tmp_path / "x")], capsys))
        declared = schema["properties"]["error"]["required"]
        assert set(declared) <= set(error)

    def test_every_finding_kind_in_the_schema_is_reachable(self, schema):
        """An enumerated value nothing can produce is a documentation error."""
        from encryption_helper import inventory

        declared = set(
            schema["properties"]["result"]["properties"]["findings"]["items"][
                "properties"
            ]["kind"]["enum"]
        )
        produced = {
            value for name, value in vars(inventory).items() if name.startswith("KIND_")
        }
        assert declared == produced

    def test_every_error_code_in_the_schema_is_reachable(self, schema):
        from encryption_helper.cli._constants import ERROR_CODES

        declared = set(schema["properties"]["error"]["properties"]["code"]["enum"])
        assert declared == set(ERROR_CODES.values())

    def test_every_declared_exit_code_is_one_the_tool_uses(self, schema):
        from encryption_helper.cli._constants import ERROR_CODES

        declared = set(schema["properties"]["error"]["properties"]["exit_code"]["enum"])
        assert declared == set(ERROR_CODES)


class TestStreamSeparation:
    """Data on stdout must never be mixed with a report."""

    def test_an_error_document_goes_to_stderr(self, tmp_path, capsys):
        main(["--json", "fingerprint", str(tmp_path / "absent")])
        captured = capsys.readouterr()
        assert captured.out == ""
        assert error_of(captured.err)["code"] == "error"

    def test_a_report_moves_aside_when_stdout_carries_data(
        self, tmp_path, capsysbinary
    ):
        keys = tmp_path / "k"
        main(
            [
                "-q",
                "keygen",
                "--out-dir",
                str(keys),
                "--no-passphrase",
                "--algorithm",
                "mlkem",
            ]
        )
        source = tmp_path / "m.txt"
        source.write_bytes(b"payload")
        capsysbinary.readouterr()
        main(
            [
                "--json",
                "encrypt",
                "--public-key",
                str(keys / "key.pub.pem"),
                "--in",
                str(source),
                "--out",
                "-",
            ]
        )
        captured = capsysbinary.readouterr()
        # stdout carries raw ciphertext, so it is read as bytes; the report is
        # on stderr and must still parse as JSON.
        assert captured.out.startswith(b"EHEV")
        assert result_of(captured.err.decode())["bytes"] == 7
