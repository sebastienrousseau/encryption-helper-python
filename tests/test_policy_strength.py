# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""NIST's transition dates follow security strength, not algorithm family.

Every classical algorithm used to be reported as "deprecated 2030,
disallowed 2035". That is right only for 112-bit keys. It overstated the
urgency for RSA-3072, P-256, Ed25519 and X25519, which NIST IR 8547 moves
straight to disallowed after 2035. Worse, it understated the urgency for
keys an inventory scan finds in the wild, such as RSA-1024: NIST SP 800-131A
has disallowed those since the end of 2013, so a 2030 date there is wrong.

Clients use these values to plan and fund migration work. These tests pin
the dates to the strength rules NIST publishes.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from encryption_helper.cli import EXIT_OK, main
from encryption_helper.inventory import classify, scan, summarise
from encryption_helper.policy import (
    NIST_DEPRECATED_FROM,
    NIST_DISALLOWED_FROM,
    NIST_LEGACY_DISALLOWED_FROM,
    assess,
    horizon,
    security_strength,
)

from ._support import result_of


def _public_pem(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


class TestSecurityStrength:
    @pytest.mark.parametrize(
        ("algorithm", "key_size", "bits"),
        [
            ("rsa", 1024, 80),
            ("rsa", 2048, 112),
            ("rsa", 2560, 112),
            ("rsa", 3072, 128),
            ("rsa", 4096, 128),
            ("rsa", 7680, 192),
            ("rsa", 15360, 256),
            ("ecdsa", 192, 96),
            ("ecdsa", 224, 112),
            ("ecdsa", 256, 128),
            ("ecdsa", 384, 192),
            ("ecdsa", 521, 260),
            ("ed25519", None, 128),
            ("x25519", None, 128),
            ("ed448", None, 224),
        ],
    )
    def test_it_matches_sp_800_57(self, algorithm, key_size, bits):
        assert security_strength(algorithm, key_size) == bits

    @pytest.mark.parametrize("algorithm", ["rsa", "ecdsa", "mlkem", "mldsa"])
    def test_unknown_without_a_size_or_for_post_quantum(self, algorithm):
        assert security_strength(algorithm) is None

    @pytest.mark.parametrize(("algorithm", "level"), [("mlkem", 768), ("mldsa", 65)])
    def test_post_quantum_has_no_classical_figure_even_with_a_level(
        self, algorithm, level
    ):
        """A parameter set is not a modulus; reading 768 as bits would mislead."""
        assert security_strength(algorithm, level) is None


class TestDatesFollowStrength:
    @pytest.mark.parametrize(
        ("algorithm", "key_size"),
        [("rsa", 3072), ("rsa", 4096), ("ecdsa", 256), ("ecdsa", 384)],
    )
    def test_128_bit_and_above_skip_the_2030_deprecation(self, algorithm, key_size):
        posture = assess(algorithm, key_size=key_size)
        assert posture.deprecated_from is None
        assert posture.disallowed_from == NIST_DISALLOWED_FROM
        assert str(NIST_DEPRECATED_FROM) not in posture.rationale

    @pytest.mark.parametrize("algorithm", ["ed25519", "ed448", "x25519"])
    def test_fixed_size_curves_skip_the_2030_deprecation(self, algorithm):
        posture = assess(algorithm)
        assert posture.deprecated_from is None
        assert posture.disallowed_from == NIST_DISALLOWED_FROM

    @pytest.mark.parametrize(("algorithm", "key_size"), [("rsa", 2048), ("ecdsa", 224)])
    def test_112_bit_keys_are_deprecated_after_2030(self, algorithm, key_size):
        posture = assess(algorithm, key_size=key_size)
        assert posture.deprecated_from == NIST_DEPRECATED_FROM
        assert posture.disallowed_from == NIST_DISALLOWED_FROM

    @pytest.mark.parametrize(("algorithm", "key_size"), [("rsa", 1024), ("ecdsa", 192)])
    def test_below_112_bit_is_already_disallowed(self, algorithm, key_size):
        posture = assess(algorithm, key_size=key_size)
        assert posture.disallowed_from == NIST_LEGACY_DISALLOWED_FROM
        assert posture.action_required is True
        assert "SP 800-131A" in posture.rationale
        assert "Replace it now" in posture.rationale

    def test_rsa_of_unknown_size_takes_the_earlier_date_and_says_why(self):
        """Understating urgency is the worse error, so unknown RSA is 2030."""
        posture = assess("rsa")
        assert posture.deprecated_from == NIST_DEPRECATED_FROM
        assert "unknown" in posture.rationale

    @pytest.mark.parametrize(
        ("algorithm", "key_size"), [("rsa", 3072), ("ed25519", None), ("rsa", 1024)]
    )
    def test_nist_wording_is_after_not_from(self, algorithm, key_size):
        """NIST says "after 2035": use is acceptable to the end of that year."""
        rationale = assess(algorithm, key_size=key_size).rationale
        assert " from 20" not in rationale

    def test_the_horizon_publishes_the_legacy_date_and_its_source(self):
        published = horizon()
        assert published["legacy_disallowed_from"] == NIST_LEGACY_DISALLOWED_FROM
        assert any("SP 800-131A" in ref for ref in published["references"])


class TestScanReportsLegacyKeys:
    @pytest.fixture
    def tree(self, tmp_path):
        (tmp_path / "legacy.pub").write_bytes(
            # Deliberately weak: the scanner must recognise what it finds in
            # the wild, and RSA-1024 is exactly what an inventory turns up.
            _public_pem(rsa.generate_private_key(65537, 1024))  # noqa: S505
        )
        (tmp_path / "current.pub").write_bytes(
            _public_pem(rsa.generate_private_key(65537, 3072))
        )
        (tmp_path / "p224.pub").write_bytes(
            _public_pem(ec.generate_private_key(ec.SECP224R1()))
        )
        return tmp_path

    def test_each_key_gets_its_own_timetable(self, tree):
        legacy = classify(tree / "legacy.pub")
        current = classify(tree / "current.pub")
        p224 = classify(tree / "p224.pub")
        assert legacy is not None
        assert current is not None
        assert p224 is not None
        assert legacy.disallowed_from == NIST_LEGACY_DISALLOWED_FROM
        assert (current.deprecated_from, current.disallowed_from) == (
            None,
            NIST_DISALLOWED_FROM,
        )
        assert p224.deprecated_from == NIST_DEPRECATED_FROM

    def test_the_summary_counts_keys_already_out_of_policy(self, tree):
        assert summarise(scan([tree]))["below_minimum_strength"] == 1

    def test_the_table_says_replace_now(self, tree, capsys):
        assert main(["scan", str(tree)]) == EXIT_OK
        out = capsys.readouterr().out
        legacy_row = next(line for line in out.splitlines() if "legacy.pub" in line)
        assert "replace now" in legacy_row
        assert "already disallowed" in out

    def test_json_carries_the_count(self, tree, capsys):
        main(["--json", "scan", str(tree)])
        payload = result_of(capsys.readouterr().out)
        assert payload["summary"]["below_minimum_strength"] == 1


class TestCapabilitiesTable:
    def test_only_rsa_shows_the_2030_step(self, capsys):
        assert main(["--json", "capabilities"]) == EXIT_OK
        algorithms = result_of(capsys.readouterr().out)["algorithms"]
        stepped = sorted(
            name
            for name, info in algorithms.items()
            if info["deprecated_from"] is not None
        )
        assert stepped == ["rsa"]

    def test_the_human_table_does_not_claim_2030_for_curves(self, capsys):
        main(["capabilities"])
        out = capsys.readouterr().out
        ed25519 = next(line for line in out.splitlines() if line.startswith("ed25519"))
        assert "2030" not in ed25519
        assert "disallowed after 2035" in ed25519


class TestKeygenNote:
    def test_rsa_3072_is_not_told_about_2030(self, tmp_path, capsys):
        main(
            [
                "keygen",
                "--algorithm",
                "rsa",
                "--key-size",
                "3072",
                "--no-passphrase",
                "--out-dir",
                str(tmp_path),
            ]
        )
        err = capsys.readouterr().err
        assert "disallows it after 2035" in err
        assert "2030" not in err

    def test_rsa_2048_is(self, tmp_path, capsys):
        main(
            [
                "keygen",
                "--algorithm",
                "rsa",
                "--key-size",
                "2048",
                "--no-passphrase",
                "--out-dir",
                str(tmp_path),
            ]
        )
        assert "deprecates it after 2030" in capsys.readouterr().err
