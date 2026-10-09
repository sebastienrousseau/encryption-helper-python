# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests for the post-quantum migration policy.

The values in :mod:`encryption_helper.policy` are quoted directly into client
and audit reports, so these tests treat the wording as part of the contract,
not only the booleans. A rationale that says a quantum computer breaks RSA
today would be wrong in a way no type checker can catch.
"""

from __future__ import annotations

import pytest
from encryption_helper import policy
from encryption_helper.errors import UnsupportedAlgorithmError
from encryption_helper.keys.generate import (
    POST_QUANTUM,
    QUANTUM_VULNERABLE,
    SUPPORTED_ALGORITHMS,
)
from encryption_helper.policy import (
    MINIMUM_RSA_KEY_SIZE_AFTER_2030,
    NIST_DEPRECATED_FROM,
    NIST_DISALLOWED_FROM,
    assess,
    horizon,
    inventory,
    purposes,
)


class TestPolicyStaysInStepWithTheGenerator:
    """The invariants ``policy.py`` documents in place of a runtime assertion.

    A module-level ``assert`` would be stripped by ``python -O``, so these
    live here instead. The failure they guard against is adding an algorithm
    to the generator and forgetting the policy, which would report a new
    algorithm as unassessable or, worse, silently acceptable.
    """

    def test_every_supported_algorithm_is_assessable(self):
        assert frozenset(SUPPORTED_ALGORITHMS) == policy.ASSESSABLE

    def test_every_vulnerable_algorithm_is_assessable(self):
        assert QUANTUM_VULNERABLE <= policy.ASSESSABLE

    def test_every_post_quantum_algorithm_is_assessable(self):
        assert POST_QUANTUM <= policy.ASSESSABLE

    @pytest.mark.parametrize("algorithm", sorted(QUANTUM_VULNERABLE))
    def test_every_vulnerable_algorithm_has_a_replacement(self, algorithm):
        """An algorithm with a deadline and no replacement is a dead end."""
        posture = assess(algorithm)
        assert posture.replacements
        assert set(posture.replacements) <= POST_QUANTUM

    @pytest.mark.parametrize("algorithm", sorted(SUPPORTED_ALGORITHMS))
    def test_every_algorithm_has_at_least_one_purpose(self, algorithm):
        able = purposes(algorithm)
        assert able["encrypt"] or able["sign"]

    @pytest.mark.parametrize("algorithm", sorted(SUPPORTED_ALGORITHMS))
    def test_a_replacement_can_do_what_it_replaces(self, algorithm):
        """Recommending ML-KEM to replace a signing key would be useless."""
        posture = assess(algorithm)
        if not posture.replacements:
            pytest.skip("no migration required")
        original = purposes(algorithm)
        covered = {
            name
            for replacement in posture.replacements
            for name, able in purposes(replacement).items()
            if able
        }
        # Every purpose the original serves must be served by something in
        # the recommendation. RSA encrypts and signs, and no single
        # post-quantum algorithm does both, so it needs two.
        for name, able in original.items():
            if able:
                assert name in covered, (algorithm, posture.replacements)


class TestClassicalAlgorithms:
    @pytest.mark.parametrize("algorithm", sorted(QUANTUM_VULNERABLE))
    def test_they_are_reported_as_vulnerable_and_needing_action(self, algorithm):
        posture = assess(algorithm)
        assert posture.quantum_vulnerable is True
        assert posture.post_quantum is False
        assert posture.action_required is True
        assert posture.disallowed_from == NIST_DISALLOWED_FROM

    def test_rsa_below_3072_is_deprecated_on_the_earlier_date(self):
        """RSA-2048 is 112-bit security, which NIST deprecates after 2030."""
        posture = assess("rsa", key_size=2048)
        assert posture.deprecated_from == NIST_DEPRECATED_FROM
        assert "112-bit security strength" in posture.rationale

    @pytest.mark.parametrize("key_size", [3072, 4096])
    def test_larger_rsa_is_not_described_as_112_bit(self, key_size):
        assert "112-bit" not in assess("rsa", key_size=key_size).rationale

    def test_rsa_without_a_size_is_still_assessable(self):
        """A scan of a certificate may not have established the modulus."""
        posture = assess("rsa")
        assert posture.quantum_vulnerable is True
        assert "RSA" in posture.rationale

    def test_the_rsa_threshold_is_the_published_constant(self):
        assert MINIMUM_RSA_KEY_SIZE_AFTER_2030 == 3072

    def test_encryption_only_keys_migrate_to_mlkem(self):
        assert assess("x25519").replacement == "mlkem"

    def test_rsa_alone_is_ambiguous_because_it_both_encrypts_and_signs(self):
        """Recommending ML-KEM for an RSA signing key would be wrong."""
        posture = assess("rsa")
        assert posture.replacements == ("mlkem", "mldsa")
        assert posture.replacement is None
        assert posture.action_required is True

    @pytest.mark.parametrize(
        ("purpose", "expected"), [("encrypt", "mlkem"), ("sign", "mldsa")]
    )
    def test_naming_the_purpose_resolves_rsa(self, purpose, expected):
        assert assess("rsa", purpose=purpose).replacement == expected

    @pytest.mark.parametrize("algorithm", ["ed25519", "ed448", "ecdsa"])
    def test_signing_keys_migrate_to_mldsa(self, algorithm):
        assert assess(algorithm).replacement == "mldsa"


class TestPostQuantumAlgorithms:
    @pytest.mark.parametrize("algorithm", sorted(POST_QUANTUM))
    def test_they_need_no_migration(self, algorithm):
        posture = assess(algorithm)
        assert posture.quantum_vulnerable is False
        assert posture.post_quantum is True
        assert posture.action_required is False
        assert posture.replacement is None
        assert posture.deprecated_from is None
        assert posture.disallowed_from is None

    def test_mlkem_cites_fips_203(self):
        assert "FIPS 203" in assess("mlkem").rationale

    def test_mldsa_cites_fips_204(self):
        assert "FIPS 204" in assess("mldsa").rationale


class TestWordingIsDefensible:
    """These strings reach client reports verbatim.

    The library's own docstring states that a quantum-vulnerable key is not
    broken today. A rationale asserting the present tense would contradict
    it, and would be factually wrong.
    """

    @pytest.mark.parametrize("algorithm", sorted(SUPPORTED_ALGORITHMS))
    def test_no_rationale_claims_a_quantum_computer_exists(self, algorithm):
        rationale = assess(algorithm).rationale
        assert "is broken by a cryptanalytically relevant" not in rationale
        assert "is broken by a quantum" not in rationale

    @pytest.mark.parametrize("algorithm", sorted(QUANTUM_VULNERABLE))
    def test_vulnerable_rationales_are_conditional(self, algorithm):
        assert "would be broken" in assess(algorithm).rationale

    @pytest.mark.parametrize("algorithm", sorted(QUANTUM_VULNERABLE))
    def test_nist_is_cited_as_a_draft(self, algorithm):
        """IR 8547 is an initial public draft, not a final publication."""
        assert "initial public draft" in assess(algorithm).rationale

    @pytest.mark.parametrize("algorithm", sorted(SUPPORTED_ALGORITHMS))
    def test_no_rationale_claims_a_fips_validation(self, algorithm):
        rationale = assess(algorithm).rationale
        for claim in ("FIPS validated", "FIPS-validated", "FIPS compliant"):
            assert claim not in rationale


class TestValidationNote:
    """The note must distinguish using an algorithm from holding a validation."""

    def test_it_states_that_validation_is_not_this_library(self):
        note = policy.VALIDATION_NOTE
        assert "not to this library" in note
        assert "cryptography" in note

    def test_it_is_carried_with_the_horizon(self):
        """A report quoting the dates must be able to quote the caveat too."""
        assert horizon()["validation_note"] == policy.VALIDATION_NOTE

    def test_the_references_name_the_draft_status(self):
        assert any("initial public draft" in ref for ref in policy.REFERENCES)


class TestHorizon:
    def test_it_reports_both_dates(self):
        assert horizon()["deprecated_from"] == NIST_DEPRECATED_FROM
        assert horizon()["disallowed_from"] == NIST_DISALLOWED_FROM

    def test_deprecation_precedes_prohibition(self):
        assert NIST_DEPRECATED_FROM < NIST_DISALLOWED_FROM

    def test_it_is_json_serialisable(self):
        import json

        assert json.loads(json.dumps(horizon()))["disallowed_from"] == 2035


class TestUnknownAlgorithms:
    def test_an_unknown_name_is_refused_rather_than_cleared(self):
        """Reporting an unknown algorithm as safe is the dangerous answer."""
        with pytest.raises(UnsupportedAlgorithmError, match="not a supported"):
            assess("rsa-but-worse")

    def test_the_error_lists_what_is_supported(self):
        with pytest.raises(UnsupportedAlgorithmError) as excinfo:
            assess("dsa")
        for name in SUPPORTED_ALGORITHMS:
            assert name in str(excinfo.value)


class TestSerialisation:
    def test_as_dict_round_trips_through_json(self):
        import json

        payload = json.loads(json.dumps(assess("rsa", key_size=2048).as_dict()))
        assert payload["algorithm"] == "rsa"
        assert payload["key_size"] == 2048
        assert payload["action_required"] is True

    def test_as_dict_exposes_action_required(self):
        """It is a property, so it would be absent from a naive asdict()."""
        assert "action_required" in assess("mlkem").as_dict()

    def test_inventory_covers_every_algorithm(self):
        table = inventory()
        assert set(table) == set(SUPPORTED_ALGORITHMS)

    def test_inventory_includes_purposes(self):
        assert inventory()["x25519"]["purposes"] == {"encrypt": True, "sign": False}

    def test_inventory_is_json_serialisable(self):
        import json

        assert json.loads(json.dumps(inventory()))["rsa"]["quantum_vulnerable"] is True


class TestPostureIsImmutable:
    def test_a_posture_cannot_be_edited_after_assessment(self):
        """A report must not be able to downgrade its own finding."""
        posture = assess("rsa", key_size=2048)
        with pytest.raises((AttributeError, TypeError)):
            posture.quantum_vulnerable = False  # type: ignore[misc]
