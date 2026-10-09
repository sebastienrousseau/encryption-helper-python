# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests for key generation."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from encryption_helper.errors import InvalidArgumentError, UnsupportedAlgorithmError
from encryption_helper.keys import (
    ALLOWED_RSA_KEY_SIZES,
    DEFAULT_RSA_KEY_SIZE,
    MIN_RSA_KEY_SIZE,
    generate,
    generate_ecdsa,
    generate_ed25519,
    generate_rsa,
)


class TestGenerateRSA:
    def test_default_size_is_3072(self):
        assert DEFAULT_RSA_KEY_SIZE == 3072

    @pytest.mark.parametrize("size", [2048, 3072])
    def test_honours_requested_size(self, size):
        assert generate_rsa(key_size=size).key_size == size

    def test_public_exponent_is_f4(self, rsa_key):
        assert rsa_key.public_key().public_numbers().e == 65537

    @pytest.mark.parametrize("size", [0, 1, 512, 1024, 2047])
    def test_rejects_weak_key_sizes(self, size):
        """Weak sizes are rejected outright rather than warned about."""
        with pytest.raises(InvalidArgumentError, match="too small"):
            generate_rsa(key_size=size)

    def test_minimum_is_2048(self):
        assert MIN_RSA_KEY_SIZE == 2048

    @pytest.mark.parametrize("size", [2049, 3000, 4095, 8192])
    def test_rejects_sizes_outside_the_allowlist(self, size):
        """An allowlist, not just a floor.

        The underlying library accepts many sizes that clear the 2048 minimum
        but interoperate poorly. Those are refused too.
        """
        with pytest.raises(InvalidArgumentError, match="not an allowed size"):
            generate_rsa(key_size=size)

    def test_allowlist_contents(self):
        assert ALLOWED_RSA_KEY_SIZES == (2048, 3072, 4096)

    def test_rejects_unsupported_exponent(self):
        with pytest.raises(InvalidArgumentError, match="public exponent"):
            generate_rsa(public_exponent=5)

    def test_generates_distinct_keys(self):
        a = generate_rsa(key_size=2048).private_numbers().p
        b = generate_rsa(key_size=2048).private_numbers().p
        assert a != b


class TestGenerateEd25519:
    def test_returns_ed25519_key(self, ed25519_key):
        assert isinstance(ed25519_key, ed25519.Ed25519PrivateKey)

    def test_generates_distinct_keys(self):
        from encryption_helper.keys import encode_private_key

        assert encode_private_key(generate_ed25519()) != encode_private_key(
            generate_ed25519()
        )


class TestGenerateECDSA:
    @pytest.mark.parametrize(
        ("curve", "expected"),
        [("p256", "secp256r1"), ("p384", "secp384r1"), ("p521", "secp521r1")],
    )
    def test_supported_curves(self, curve, expected):
        assert generate_ecdsa(curve=curve).curve.name == expected

    def test_curve_name_is_case_insensitive(self):
        assert generate_ecdsa(curve="P256").curve.name == "secp256r1"

    def test_rejects_unknown_curve(self):
        with pytest.raises(UnsupportedAlgorithmError, match="Unsupported curve"):
            generate_ecdsa(curve="p192")


class TestGenerateDispatcher:
    @pytest.mark.parametrize(
        ("algorithm", "expected"),
        [
            ("rsa", rsa.RSAPrivateKey),
            ("ed25519", ed25519.Ed25519PrivateKey),
            ("ecdsa", ec.EllipticCurvePrivateKey),
        ],
    )
    def test_dispatches_by_algorithm(self, algorithm, expected):
        assert isinstance(generate(algorithm, key_size=2048), expected)

    def test_algorithm_is_case_and_space_insensitive(self):
        assert isinstance(generate("  RSA  ", key_size=2048), rsa.RSAPrivateKey)

    def test_defaults_to_rsa(self):
        assert isinstance(generate(key_size=2048), rsa.RSAPrivateKey)

    def test_rejects_unknown_algorithm(self):
        with pytest.raises(UnsupportedAlgorithmError, match="Unsupported algorithm"):
            generate("dsa")

    def test_propagates_parameter_errors(self):
        with pytest.raises(InvalidArgumentError):
            generate("rsa", key_size=1024)


class TestPostQuantumGeneration:
    """ML-KEM (FIPS 203) and ML-DSA (FIPS 204).

    These are the only algorithms here that survive a quantum computer, and
    the only ones NIST permits past 2035.
    """

    @pytest.mark.parametrize("level", [768, 1024])
    def test_mlkem_levels(self, level):
        from encryption_helper.keys import generate_mlkem

        assert type(generate_mlkem(level=level)).__name__ == f"MLKEM{level}PrivateKey"

    @pytest.mark.parametrize("level", [44, 65, 87])
    def test_mldsa_levels(self, level):
        from encryption_helper.keys import generate_mldsa

        assert type(generate_mldsa(level=level)).__name__ == f"MLDSA{level}PrivateKey"

    @pytest.mark.parametrize("level", [0, 1, 512, 2048])
    def test_mlkem_rejects_unknown_levels(self, level):
        from encryption_helper.keys import generate_mlkem

        with pytest.raises(UnsupportedAlgorithmError, match="Unsupported ML-KEM"):
            generate_mlkem(level=level)

    @pytest.mark.parametrize("level", [0, 1, 43, 88, 128])
    def test_mldsa_rejects_unknown_levels(self, level):
        from encryption_helper.keys import generate_mldsa

        with pytest.raises(UnsupportedAlgorithmError, match="Unsupported ML-DSA"):
            generate_mldsa(level=level)

    def test_defaults_are_the_documented_levels(self):
        from encryption_helper.keys import (
            DEFAULT_MLDSA_LEVEL,
            DEFAULT_MLKEM_LEVEL,
            generate,
        )

        assert DEFAULT_MLKEM_LEVEL == 768
        assert DEFAULT_MLDSA_LEVEL == 65
        assert type(generate("mlkem")).__name__ == "MLKEM768PrivateKey"
        assert type(generate("mldsa")).__name__ == "MLDSA65PrivateKey"

    def test_generates_distinct_keys(self):
        from encryption_helper.keys import encode_public_key, generate_mlkem

        a = encode_public_key(generate_mlkem().public_key(), fmt="der")
        b = encode_public_key(generate_mlkem().public_key(), fmt="der")
        assert a != b


class TestQuantumVulnerabilityMetadata:
    """The horizon is a published date, so the package records it rather than
    leaving users to discover it. NIST IR 8547: disallowed after 2035, and
    112-bit keys deprecated after 2030."""

    def test_classical_algorithms_are_marked_vulnerable(self):
        from encryption_helper.keys import QUANTUM_VULNERABLE

        assert {"rsa", "ecdsa", "ed25519", "ed448", "x25519"} == set(QUANTUM_VULNERABLE)

    def test_post_quantum_algorithms_are_marked_safe(self):
        from encryption_helper.keys import POST_QUANTUM

        assert {"mlkem", "mldsa"} == set(POST_QUANTUM)

    def test_the_two_sets_are_disjoint_and_cover_everything(self):
        from encryption_helper.keys import (
            POST_QUANTUM,
            QUANTUM_VULNERABLE,
            SUPPORTED_ALGORITHMS,
        )

        assert not (POST_QUANTUM & QUANTUM_VULNERABLE)
        assert set(SUPPORTED_ALGORITHMS) == POST_QUANTUM | QUANTUM_VULNERABLE
