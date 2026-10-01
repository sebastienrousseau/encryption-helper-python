# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""CLI coverage for the post-quantum algorithms and the agility surface.

NIST IR 8547 deprecates the classical algorithms from 2030 and disallows them
from 2035. The CLI has to make that discoverable without the user reading a
standard, and it has to make the post-quantum choice as easy as the classical
one.
"""

from __future__ import annotations

import json
import stat

import pytest
from encryption_helper.cli import EXIT_OK, EXIT_USAGE, main
from encryption_helper.keys import POST_QUANTUM, QUANTUM_VULNERABLE

from ._support import posix_only


def keygen(tmp_path, *extra: str) -> list[str]:
    return ["keygen", "--out-dir", str(tmp_path), "--no-passphrase", *extra]


class TestCapabilities:
    def test_human_output_lists_every_algorithm(self, capsys):
        assert main(["capabilities"]) == EXIT_OK
        out = capsys.readouterr().out
        for algorithm in QUANTUM_VULNERABLE | POST_QUANTUM:
            assert algorithm in out

    def test_human_output_states_the_horizon(self, capsys):
        main(["capabilities"])
        out = capsys.readouterr().out
        assert "2030" in out
        assert "2035" in out
        assert "NIST IR 8547" in out

    def test_json_is_machine_readable(self, capsys):
        assert main(["--json", "capabilities"]) == EXIT_OK
        caps = json.loads(capsys.readouterr().out)
        assert caps["algorithms"]["mlkem"]["post_quantum"] is True
        assert caps["algorithms"]["mlkem"]["deprecated_from"] is None
        assert caps["algorithms"]["rsa"]["post_quantum"] is False
        assert caps["algorithms"]["rsa"]["deprecated_from"] == 2030
        assert caps["algorithms"]["rsa"]["disallowed_from"] == 2035

    def test_json_reports_capability_per_algorithm(self, capsys):
        main(["--json", "capabilities"])
        caps = json.loads(capsys.readouterr().out)["algorithms"]
        expected = {
            "mlkem": (True, False),
            "mldsa": (False, True),
            "rsa": (True, True),
            "x25519": (True, False),
            "ed25519": (False, True),
        }
        actual = {
            name: (caps[name]["can_encrypt"], caps[name]["can_sign"])
            for name in expected
        }
        assert actual == expected

    def test_json_lists_container_mechanisms(self, capsys):
        main(["--json", "capabilities"])
        caps = json.loads(capsys.readouterr().out)
        assert caps["container_kems"] == [1, 2, 3, 4]
        assert caps["quantum_vulnerable_kems"] == [1, 4]

    def test_json_lists_parameter_sets(self, capsys):
        main(["--json", "capabilities"])
        caps = json.loads(capsys.readouterr().out)
        assert caps["mlkem_levels"] == [768, 1024]
        assert caps["mldsa_levels"] == [44, 65, 87]
        assert caps["rsa_key_sizes"] == [2048, 3072, 4096]


class TestDeprecationNotice:
    @pytest.mark.parametrize("algorithm", sorted(QUANTUM_VULNERABLE))
    def test_classical_algorithms_warn(self, tmp_path, capsys, algorithm):
        extra = ["--algorithm", algorithm]
        if algorithm == "rsa":
            extra += ["--key-size", "2048"]
        assert main(keygen(tmp_path, *extra)) == EXIT_OK
        err = capsys.readouterr().err
        assert "quantum" in err
        assert "2035" in err

    @pytest.mark.parametrize("algorithm", sorted(POST_QUANTUM))
    def test_post_quantum_algorithms_do_not_warn(self, tmp_path, capsys, algorithm):
        assert main(keygen(tmp_path, "--algorithm", algorithm)) == EXIT_OK
        assert "broken by a quantum computer" not in capsys.readouterr().err

    def test_quiet_silences_the_notice(self, tmp_path, capsys):
        main(["--quiet", *keygen(tmp_path, "--algorithm", "ed25519")])
        assert capsys.readouterr().err == ""

    def test_the_notice_names_the_alternatives(self, tmp_path, capsys):
        main(keygen(tmp_path, "--algorithm", "ed25519"))
        err = capsys.readouterr().err
        assert "mlkem" in err
        assert "mldsa" in err


class TestPostQuantumKeygen:
    @pytest.mark.parametrize("level", [768, 1024])
    def test_mlkem_levels(self, tmp_path, level, capsys):
        args = keygen(tmp_path, "--algorithm", "mlkem", "--level", str(level))
        assert main(args) == EXIT_OK
        assert f"Parameter set: {level}" in capsys.readouterr().out

    @pytest.mark.parametrize("level", [44, 65, 87])
    def test_mldsa_levels(self, tmp_path, level, capsys):
        args = keygen(tmp_path, "--algorithm", "mldsa", "--level", str(level))
        assert main(args) == EXIT_OK
        assert f"Parameter set: {level}" in capsys.readouterr().out

    def test_parameter_sets_are_not_reported_as_bits(self, tmp_path, capsys):
        """Calling ML-KEM-768 "768 bits" would simply be wrong."""
        main(keygen(tmp_path, "--algorithm", "mlkem"))
        out = capsys.readouterr().out
        assert "Parameter set: 768" in out
        assert "768 bits" not in out

    def test_classical_sizes_are_still_reported_as_bits(self, tmp_path, capsys):
        main(keygen(tmp_path, "--algorithm", "rsa", "--key-size", "2048"))
        assert "Key size:     2048 bits" in capsys.readouterr().out

    def test_json_distinguishes_parameter_set_from_key_size(self, tmp_path, capsys):
        main(["--json", *keygen(tmp_path, "--algorithm", "mlkem")])
        payload = json.loads(capsys.readouterr().out)
        assert payload["parameter_set"] == 768
        assert payload["post_quantum"] is True

    def test_json_marks_classical_keys(self, tmp_path, capsys):
        args = keygen(tmp_path, "--algorithm", "rsa", "--key-size", "2048")
        main(["--json", *args])
        payload = json.loads(capsys.readouterr().out)
        assert payload["parameter_set"] is None
        assert payload["post_quantum"] is False

    @posix_only
    @pytest.mark.parametrize("algorithm", ["mlkem", "mldsa", "x25519", "ed448"])
    def test_private_key_is_owner_only(self, tmp_path, algorithm):
        main(keygen(tmp_path, "--algorithm", algorithm))
        assert stat.S_IMODE((tmp_path / "key.pem").stat().st_mode) == 0o600

    def test_invalid_level_is_rejected(self, tmp_path, capsys):
        args = keygen(tmp_path, "--algorithm", "mlkem", "--level", "999")
        assert main(args) != EXIT_OK
        assert "Unsupported ML-KEM" in capsys.readouterr().err


class TestPostQuantumRoundTrips:
    @pytest.mark.parametrize("algorithm", ["mlkem", "x25519"])
    def test_encrypt_decrypt(self, tmp_path, algorithm):
        keys = tmp_path / "k"
        assert main(keygen(keys, "--algorithm", algorithm)) == EXIT_OK
        (tmp_path / "m.txt").write_bytes(b"post-quantum payload")

        assert (
            main(
                [
                    "-q",
                    "encrypt",
                    "--public-key",
                    str(keys / "key.pub.pem"),
                    "--in",
                    str(tmp_path / "m.txt"),
                    "--out",
                    str(tmp_path / "m.bin"),
                ]
            )
            == EXIT_OK
        )
        assert (
            main(
                [
                    "-q",
                    "decrypt",
                    "--private-key",
                    str(keys / "key.pem"),
                    "--in",
                    str(tmp_path / "m.bin"),
                    "--out",
                    str(tmp_path / "out.txt"),
                ]
            )
            == EXIT_OK
        )
        assert (tmp_path / "out.txt").read_bytes() == b"post-quantum payload"

    @pytest.mark.parametrize("algorithm", ["mldsa", "ed448"])
    def test_sign_verify(self, tmp_path, algorithm):
        keys = tmp_path / "k"
        main(keygen(keys, "--algorithm", algorithm))
        (tmp_path / "m.txt").write_bytes(b"release manifest")

        assert (
            main(
                [
                    "-q",
                    "sign",
                    "--private-key",
                    str(keys / "key.pem"),
                    "--in",
                    str(tmp_path / "m.txt"),
                    "--out",
                    str(tmp_path / "m.sig"),
                ]
            )
            == EXIT_OK
        )
        assert (
            main(
                [
                    "verify",
                    "--public-key",
                    str(keys / "key.pub.pem"),
                    "--signature",
                    str(tmp_path / "m.sig"),
                    "--in",
                    str(tmp_path / "m.txt"),
                ]
            )
            == EXIT_OK
        )


class TestInputSizeCeiling:
    """Encryption is not streamed; peak memory is about four times the
    payload. Refusing is better than an out-of-memory kill mid-write."""

    def test_oversized_file_is_refused(self, tmp_path, capsys):
        keys = tmp_path / "k"
        main(keygen(keys, "--algorithm", "x25519"))
        big = tmp_path / "big.bin"
        big.write_bytes(b"x" * 2048)

        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "encrypt",
                    "--public-key",
                    str(keys / "key.pub.pem"),
                    "--in",
                    str(big),
                    "--out",
                    str(tmp_path / "o.bin"),
                    "--max-size",
                    "1024",
                ]
            )
        assert excinfo.value.code == EXIT_USAGE
        assert "exceeds the 1024-byte limit" in capsys.readouterr().err
        assert not (tmp_path / "o.bin").exists()

    def test_file_at_the_limit_is_accepted(self, tmp_path):
        keys = tmp_path / "k"
        main(keygen(keys, "--algorithm", "x25519"))
        payload = tmp_path / "ok.bin"
        payload.write_bytes(b"x" * 1024)
        assert (
            main(
                [
                    "-q",
                    "encrypt",
                    "--public-key",
                    str(keys / "key.pub.pem"),
                    "--in",
                    str(payload),
                    "--out",
                    str(tmp_path / "o.bin"),
                    "--max-size",
                    "1024",
                ]
            )
            == EXIT_OK
        )

    def test_oversized_stdin_is_refused(self, tmp_path, monkeypatch, capsys):
        import io

        keys = tmp_path / "k"
        main(keygen(keys, "--algorithm", "x25519"))
        monkeypatch.setattr(
            "sys.stdin",
            type("S", (), {"buffer": io.BytesIO(b"y" * 4096)})(),
        )
        with pytest.raises(SystemExit) as excinfo:
            main(
                [
                    "encrypt",
                    "--public-key",
                    str(keys / "key.pub.pem"),
                    "--in",
                    "-",
                    "--out",
                    str(tmp_path / "o.bin"),
                    "--max-size",
                    "1024",
                ]
            )
        assert excinfo.value.code == EXIT_USAGE
        assert "exceeds the 1024-byte limit" in capsys.readouterr().err


class TestJsonStreamSeparation:
    """`--json` with `--out -` used to interleave a JSON object with binary
    output on one stream, leaving neither parseable."""

    def test_report_moves_to_stderr_when_stdout_carries_output(
        self, tmp_path, capsysbinary
    ):
        keys = tmp_path / "k"
        main(keygen(keys, "--algorithm", "x25519"))
        (tmp_path / "m.txt").write_bytes(b"payload")
        capsysbinary.readouterr()  # discard the keygen output

        main(
            [
                "--json",
                "encrypt",
                "--public-key",
                str(keys / "key.pub.pem"),
                "--in",
                str(tmp_path / "m.txt"),
                "--out",
                "-",
            ]
        )
        captured = capsysbinary.readouterr()
        assert captured.out.startswith(b"EHEV"), "stdout must be pure ciphertext"
        # A 0x7b byte occurs in ciphertext by chance, so "no { in stdout" is
        # not a meaningful check. What matters is that the byte count the
        # report gives equals exactly what landed on stdout -- nothing else
        # was written there.
        err = captured.err.decode()
        payload = json.loads(err[err.index("{") :])
        assert payload["output"] == "<stdout>"
        assert payload["bytes"] == len(captured.out)

    def test_report_stays_on_stdout_for_a_file_destination(self, tmp_path, capsys):
        keys = tmp_path / "k"
        main(keygen(keys, "--algorithm", "x25519"))
        (tmp_path / "m.txt").write_bytes(b"payload")
        capsys.readouterr()  # discard the keygen output
        main(
            [
                "--json",
                "encrypt",
                "--public-key",
                str(keys / "key.pub.pem"),
                "--in",
                str(tmp_path / "m.txt"),
                "--out",
                str(tmp_path / "m.bin"),
            ]
        )
        assert json.loads(capsys.readouterr().out)["bytes"] > 0


class TestEdgeCases:
    def test_unstattable_input_defers_to_the_reader(self, tmp_path, capsys):
        """A path that cannot be stat-ed must surface the real read error."""
        keys = tmp_path / "k"
        main(keygen(keys, "--algorithm", "x25519"))
        code = main(
            [
                "encrypt",
                "--public-key",
                str(keys / "key.pub.pem"),
                "--in",
                str(tmp_path / "does-not-exist.bin"),
                "--out",
                str(tmp_path / "o.bin"),
            ]
        )
        assert code != EXIT_OK
        assert "No such file" in capsys.readouterr().err

    def test_key_without_a_reportable_size(self, tmp_path, capsys, monkeypatch):
        """describe_key returns None for an unrecognised type; don't crash."""
        import encryption_helper.cli as cli_module
        from encryption_helper.keys.store import KeyGenerationResult

        real = cli_module.write_key_pair

        def sizeless(*args, **kwargs):
            result = real(*args, **kwargs)
            return KeyGenerationResult(
                private_key_path=result.private_key_path,
                public_key_path=result.public_key_path,
                algorithm="exotic",
                key_size=None,
                fingerprint=result.fingerprint,
                private_key_encrypted=result.private_key_encrypted,
            )

        monkeypatch.setattr(cli_module, "write_key_pair", sizeless)
        assert main(keygen(tmp_path, "--algorithm", "ed25519")) == EXIT_OK
        assert "Key size:     n/a" in capsys.readouterr().out
