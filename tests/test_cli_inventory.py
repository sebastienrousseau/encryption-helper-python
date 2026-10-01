# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests for the `inspect` and `scan` subcommands.

Both exist to answer a question about existing material without holding a
secret, so the tests check that property explicitly as well as the output.
"""

from __future__ import annotations

from encryption_helper import encode_public_key, encrypt, generate
from encryption_helper.cli import EXIT_ERROR, EXIT_OK, main

from ._support import result_of


def _container(tmp_path, algorithm="mlkem", name="data.enc"):
    key = generate(algorithm, key_size=2048)
    path = tmp_path / name
    path.write_bytes(encrypt(key.public_key(), b"payload"))
    return path


class TestInspect:
    def test_it_reports_the_mechanism_without_a_private_key(self, tmp_path, capsys):
        path = _container(tmp_path)
        assert main(["inspect", "--in", str(path)]) == EXIT_OK
        out = capsys.readouterr().out
        assert "ml-kem-768" in out
        assert "FIPS 203" in out

    def test_json_output_carries_the_envelope(self, tmp_path, capsys):
        path = _container(tmp_path)
        assert main(["--json", "inspect", "--in", str(path)]) == EXIT_OK
        result = result_of(capsys.readouterr().out)
        assert result["key_establishment"] == "ml-kem-768"
        assert result["quantum_vulnerable"] is False

    def test_a_classical_container_is_flagged(self, tmp_path, capsys):
        path = _container(tmp_path, algorithm="rsa")
        assert main(["inspect", "--in", str(path)]) == EXIT_OK
        assert "Vulnerable to a quantum computer" in capsys.readouterr().out

    def test_a_post_quantum_container_is_not_flagged(self, tmp_path, capsys):
        path = _container(tmp_path)
        main(["inspect", "--in", str(path)])
        assert "Not vulnerable" in capsys.readouterr().out

    def test_it_reads_only_the_header(self, tmp_path, capsys):
        """A truncated file is still describable, which proves the bound."""
        path = _container(tmp_path)
        truncated = tmp_path / "head.enc"
        truncated.write_bytes(path.read_bytes()[:10])
        assert main(["inspect", "--in", str(truncated)]) == EXIT_OK
        assert "ml-kem-768" in capsys.readouterr().out

    def test_a_segmented_container_is_reported_as_segmented(self, tmp_path, capsys):
        keys = tmp_path / "k"
        main(
            [
                "-q",
                "keygen",
                "--out-dir",
                str(keys),
                "--algorithm",
                "mlkem",
                "--no-passphrase",
            ]
        )
        source = tmp_path / "big.bin"
        source.write_bytes(b"x" * 100_000)
        main(
            [
                "-q",
                "encrypt",
                "--public-key",
                str(keys / "key.pub.pem"),
                "--in",
                str(source),
                "--out",
                str(tmp_path / "big.enc"),
            ]
        )
        main(["inspect", "--in", str(tmp_path / "big.enc")])
        assert "Segmented:          yes" in capsys.readouterr().out

    def test_a_non_container_is_a_clean_error(self, tmp_path, capsys):
        path = tmp_path / "notes.txt"
        path.write_text("this is not a container at all")
        assert main(["inspect", "--in", str(path)]) != EXIT_OK
        assert "not produced by this library" in capsys.readouterr().err

    def test_the_error_is_structured_under_json(self, tmp_path, capsys):
        from ._support import error_of

        path = tmp_path / "notes.txt"
        path.write_text("this is not a container at all")
        assert main(["--json", "inspect", "--in", str(path)]) != EXIT_OK
        error = error_of(capsys.readouterr().err)
        assert error["code"] == "error"
        assert error["exit_code"] == EXIT_ERROR


class TestScan:
    def _tree(self, tmp_path):
        vulnerable = generate("rsa", key_size=2048)
        (tmp_path / "legacy.pub").write_bytes(
            encode_public_key(vulnerable.public_key())
        )
        modern = generate("mlkem")
        (tmp_path / "modern.pub").write_bytes(encode_public_key(modern.public_key()))
        (tmp_path / "notes.txt").write_text("not cryptographic")
        return tmp_path

    def test_it_reports_both_findings(self, tmp_path, capsys):
        assert main(["scan", str(self._tree(tmp_path))]) == EXIT_OK
        out = capsys.readouterr().out
        assert "legacy.pub" in out
        assert "modern.pub" in out
        assert "notes.txt" not in out

    def test_rsa_is_shown_as_needing_either_successor(self, tmp_path, capsys):
        """RSA can encrypt and sign, so one recommendation would be wrong."""
        main(["scan", str(self._tree(tmp_path))])
        assert "migrate to mlkem or mldsa" in capsys.readouterr().out

    def test_json_output_carries_summary_findings_and_horizon(self, tmp_path, capsys):
        assert main(["--json", "scan", str(self._tree(tmp_path))]) == EXIT_OK
        result = result_of(capsys.readouterr().out)
        assert result["summary"]["examined"] == 2
        assert result["summary"]["action_required"] == 1
        assert len(result["findings"]) == 2
        assert result["horizon"]["disallowed_from"] == 2035

    def test_the_horizon_carries_the_validation_note(self, tmp_path, capsys):
        """A report quoting the dates must carry the caveat that applies."""
        main(["--json", "scan", str(self._tree(tmp_path))])
        note = result_of(capsys.readouterr().out)["horizon"]["validation_note"]
        assert "not to this library" in note

    def test_it_succeeds_by_default_even_with_findings(self, tmp_path):
        """Reporting an inventory is not itself a failure."""
        assert main(["scan", str(self._tree(tmp_path))]) == EXIT_OK

    def test_fail_on_finding_gates_a_pipeline(self, tmp_path):
        assert (
            main(["scan", "--fail-on-finding", str(self._tree(tmp_path))]) == EXIT_ERROR
        )

    def test_fail_on_finding_passes_a_clean_tree(self, tmp_path):
        key = generate("mlkem")
        (tmp_path / "modern.pub").write_bytes(encode_public_key(key.public_key()))
        assert main(["scan", "--fail-on-finding", str(tmp_path)]) == EXIT_OK

    def test_an_empty_tree_says_so(self, tmp_path, capsys):
        assert main(["scan", str(tmp_path)]) == EXIT_OK
        assert "No recognised cryptographic material" in capsys.readouterr().out

    def test_several_paths_can_be_given(self, tmp_path, capsys):
        first = tmp_path / "one"
        second = tmp_path / "two"
        for directory in (first, second):
            directory.mkdir()
            key = generate("ed25519")
            (directory / "k.pub").write_bytes(encode_public_key(key.public_key()))
        main(["--json", "scan", str(first), str(second)])
        assert result_of(capsys.readouterr().out)["summary"]["examined"] == 2

    def test_quiet_suppresses_the_table(self, tmp_path, capsys):
        assert main(["-q", "scan", str(self._tree(tmp_path))]) == EXIT_OK
        assert capsys.readouterr().out == ""

    def test_no_passphrase_is_ever_requested(self, tmp_path, monkeypatch):
        """A scan is not a reason to handle a secret."""
        from encryption_helper import encode_private_key

        key = generate("rsa", key_size=2048)
        (tmp_path / "protected.pem").write_bytes(
            encode_private_key(key, passphrase=b"a-long-passphrase")
        )

        def must_not_prompt(_prompt):
            msg = "scan must never prompt for a passphrase"
            raise AssertionError(msg)

        monkeypatch.setattr("getpass.getpass", must_not_prompt)
        assert main(["scan", str(tmp_path)]) == EXIT_OK

    def test_an_encrypted_key_is_reported_for_review_not_skipped(
        self, tmp_path, capsys
    ):
        from encryption_helper import encode_private_key

        key = generate("rsa", key_size=2048)
        (tmp_path / "protected.pem").write_bytes(
            encode_private_key(key, passphrase=b"a-long-passphrase")
        )
        main(["scan", str(tmp_path)])
        out = capsys.readouterr().out
        assert "review manually" in out
        assert "undetermined" in out
