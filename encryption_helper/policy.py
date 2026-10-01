# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Post-quantum migration policy, expressed as data rather than prose.

Organisations holding long-lived keys need to answer a specific question:
which of their keys stop being acceptable, and when. NIST IR 8547 sets the
dates; this module turns them into values a program can act on, so an
inventory process does not have to parse documentation or help text.

The judgements encoded here are NIST's, not this project's. Each one cites
the publication it comes from, and :data:`REFERENCES` lists them in full.

A quantum-vulnerable key is not broken today. The exposure is that encrypted
data recorded now can be decrypted later, once a cryptanalytically relevant
quantum computer exists -- often called *harvest now, decrypt later*. Data
with a confidentiality lifetime extending past the dates below is therefore
already affected, which is why the dates matter before they arrive.

.. note::
   Using an algorithm specified in a FIPS publication is not the same as
   holding a FIPS validation. See :data:`VALIDATION_NOTE`.

Example:
    >>> posture = assess("rsa", key_size=2048)
    >>> posture.quantum_vulnerable
    True
    >>> posture.disallowed_from
    2035

    RSA can both encrypt and sign, and no single post-quantum algorithm
    replaces both, so the successor depends on how the key is used:

    >>> posture.replacements
    ('mlkem', 'mldsa')
    >>> assess("rsa", key_size=2048, purpose="sign").replacement
    'mldsa'
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from .errors import UnsupportedAlgorithmError
from .keys.generate import (
    POST_QUANTUM,
    SUPPORTED_ALGORITHMS,
)

__all__ = [
    "MINIMUM_RSA_KEY_SIZE_AFTER_2030",
    "NIST_DEPRECATED_FROM",
    "NIST_DISALLOWED_FROM",
    "REFERENCES",
    "VALIDATION_NOTE",
    "Posture",
    "assess",
    "horizon",
    "inventory",
    "purposes",
]

#: Year from which NIST IR 8547 deprecates 112-bit-security public-key
#: algorithms. Deprecated means still permitted, but carrying risk that must
#: be accepted deliberately.
NIST_DEPRECATED_FROM: Final = 2030

#: Year from which NIST IR 8547 disallows the classical public-key algorithms
#: covered here. Disallowed means no longer acceptable for new protection.
NIST_DISALLOWED_FROM: Final = 2035

#: RSA modulus size below which NIST IR 8547 withdraws approval at the
#: earlier 2030 date rather than 2035, because its security strength is
#: 112 bits rather than 128.
MINIMUM_RSA_KEY_SIZE_AFTER_2030: Final = 3072

#: Publications the judgements in this module are taken from.
REFERENCES: Final = (
    "NIST IR 8547 (initial public draft), Transition to Post-Quantum "
    "Cryptography Standards",
    "FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard",
    "FIPS 204, Module-Lattice-Based Digital Signature Standard",
)

#: Statement on validation, kept with the policy data so any report that
#: quotes the policy can quote this alongside it.
VALIDATION_NOTE: Final = (
    "This library implements algorithms specified in FIPS 203 and FIPS 204 "
    "using the cryptography package, which obtains them from OpenSSL. A FIPS "
    "validation applies to a specific cryptographic module in a specific "
    "configuration, not to this library. Where validated cryptography is "
    "required, confirm the status of the underlying module in the deployed "
    "environment."
)

#: What to move to, by purpose. Key establishment moves to ML-KEM
#: (FIPS 203); signing moves to ML-DSA (FIPS 204). There is no single
#: post-quantum algorithm that does both, which is why this is keyed by
#: purpose rather than by algorithm: RSA can encrypt and sign, so an RSA key
#: has two possible successors and which one applies depends on how the key
#: is actually used.
_REPLACEMENT_BY_PURPOSE: Final = {
    "encrypt": "mlkem",
    "sign": "mldsa",
}

#: Algorithms usable for key establishment, and so for encryption here.
_KEY_ESTABLISHMENT: Final = frozenset({"rsa", "x25519", "mlkem"})

#: Algorithms usable for digital signatures.
_SIGNATURE: Final = frozenset({"rsa", "ed25519", "ed448", "ecdsa", "mldsa"})


@dataclass(frozen=True)
class Posture:
    """Where one algorithm choice stands against the migration timetable.

    Attributes:
        algorithm: The algorithm name, as :func:`~encryption_helper.generate`
            accepts it.
        key_size: Modulus size for RSA, parameter set for ML-KEM and ML-DSA,
            or :data:`None` where the algorithm has a single fixed size.
        quantum_vulnerable: Whether a cryptanalytically relevant quantum
            computer would break this choice.
        post_quantum: Whether this choice is a NIST post-quantum standard.
        deprecated_from: Year from which use is deprecated, or :data:`None`
            if no deprecation applies.
        disallowed_from: Year from which use is disallowed, or :data:`None`
            if no prohibition applies.
        replacements: Algorithms to migrate to, empty if no migration is
            needed. More than one entry means the correct choice depends on
            how the key is used: RSA can both encrypt and sign, and no single
            post-quantum algorithm replaces both.
        rationale: One sentence a report can quote directly.
    """

    algorithm: str
    key_size: int | None
    quantum_vulnerable: bool
    post_quantum: bool
    deprecated_from: int | None
    disallowed_from: int | None
    replacements: tuple[str, ...]
    rationale: str

    @property
    def action_required(self) -> bool:
        """Whether this choice needs to change before the disallowed date."""
        return bool(self.replacements)

    @property
    def replacement(self) -> str | None:
        """The single algorithm to migrate to, if there is exactly one.

        :data:`None` where the choice is ambiguous, which for an RSA key of
        unknown purpose it genuinely is. Reporting "migrate to ML-KEM" for an
        RSA signing key would be wrong, so this declines to guess; read
        :attr:`replacements` and supply ``purpose`` to :func:`assess` to
        resolve it.
        """
        if len(self.replacements) == 1:
            return self.replacements[0]
        return None

    def as_dict(self) -> dict[str, object]:
        """Return the posture as a JSON-serialisable mapping.

        Example:
            >>> assess("mlkem", key_size=768).as_dict()["post_quantum"]
            True
        """
        return {
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "quantum_vulnerable": self.quantum_vulnerable,
            "post_quantum": self.post_quantum,
            "deprecated_from": self.deprecated_from,
            "disallowed_from": self.disallowed_from,
            "replacement": self.replacement,
            "replacements": list(self.replacements),
            "rationale": self.rationale,
            "action_required": self.action_required,
        }


def horizon() -> dict[str, object]:
    """Return the migration timetable and the publications behind it.

    Example:
        >>> horizon()["disallowed_from"]
        2035
    """
    return {
        "deprecated_from": NIST_DEPRECATED_FROM,
        "disallowed_from": NIST_DISALLOWED_FROM,
        "minimum_rsa_key_size_after_2030": MINIMUM_RSA_KEY_SIZE_AFTER_2030,
        "references": list(REFERENCES),
        "validation_note": VALIDATION_NOTE,
    }


def _rsa_rationale(key_size: int | None) -> tuple[int, str]:
    """Return RSA's deprecation year and the reason for it.

    RSA-2048 provides 112-bit security, which NIST IR 8547 withdraws from
    2030. Larger moduli remain acceptable until the 2035 prohibition, so the
    two cases carry different urgency and are reported differently.
    """
    if key_size is not None and key_size < MINIMUM_RSA_KEY_SIZE_AFTER_2030:
        return (
            NIST_DEPRECATED_FROM,
            f"RSA-{key_size} provides 112-bit security strength, which NIST "
            f"IR 8547 (initial public draft) deprecates from "
            f"{NIST_DEPRECATED_FROM} and disallows from "
            f"{NIST_DISALLOWED_FROM}. It would also be broken by a "
            "cryptanalytically relevant quantum computer, which does not "
            "exist today.",
        )
    size = f"RSA-{key_size}" if key_size is not None else "RSA"
    return (
        NIST_DEPRECATED_FROM,
        f"{size} would be broken by a cryptanalytically relevant quantum "
        "computer, which does not exist today. NIST IR 8547 (initial public "
        f"draft) deprecates it from {NIST_DEPRECATED_FROM} and disallows it "
        f"from {NIST_DISALLOWED_FROM}.",
    )


def assess(
    algorithm: str, *, key_size: int | None = None, purpose: str | None = None
) -> Posture:
    """Report where an algorithm choice stands against the NIST timetable.

    Args:
        algorithm: Algorithm name, as :func:`~encryption_helper.generate`
            accepts it.
        key_size: Modulus size for RSA, or parameter set for ML-KEM and
            ML-DSA. Optional; it refines the RSA judgement, which depends on
            the modulus.
        purpose: ``"encrypt"`` or ``"sign"``, where the key's use is known.
            This matters only for RSA, which can do both and therefore has
            two possible successors. Supplying it narrows
            :attr:`Posture.replacements` to the one that applies.

    Returns:
        The :class:`Posture` for that choice.

    Raises:
        UnsupportedAlgorithmError: If ``algorithm`` is not one this library
            supports. Reporting an unknown name as "not vulnerable" would be
            the more dangerous answer.

    Example:
        >>> assess("ed25519").replacement
        'mldsa'
        >>> assess("mldsa", key_size=65).action_required
        False
        >>> assess("rsa").replacements
        ('mlkem', 'mldsa')
        >>> assess("rsa", purpose="sign").replacement
        'mldsa'
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        msg = (
            f"Cannot assess {algorithm!r}: not a supported algorithm. "
            f"Supported: {', '.join(SUPPORTED_ALGORITHMS)}."
        )
        raise UnsupportedAlgorithmError(msg)

    if algorithm in POST_QUANTUM:
        standard = "FIPS 203" if algorithm == "mlkem" else "FIPS 204"
        return Posture(
            algorithm=algorithm,
            key_size=key_size,
            quantum_vulnerable=False,
            post_quantum=True,
            deprecated_from=None,
            disallowed_from=None,
            replacements=(),
            rationale=(
                f"{algorithm} is standardised in {standard} and is the "
                "algorithm NIST expects to carry this role past "
                f"{NIST_DISALLOWED_FROM}. No migration is required."
            ),
        )

    if algorithm == "rsa":
        deprecated, rationale = _rsa_rationale(key_size)
    else:
        deprecated = NIST_DEPRECATED_FROM
        rationale = (
            f"{algorithm} would be broken by a cryptanalytically relevant "
            "quantum computer, which does not exist today. NIST IR 8547 "
            f"(initial public draft) deprecates it from "
            f"{NIST_DEPRECATED_FROM} and disallows it from "
            f"{NIST_DISALLOWED_FROM}."
        )

    able = purposes(algorithm)
    wanted = (purpose,) if purpose is not None else ("encrypt", "sign")
    replacements = tuple(
        _REPLACEMENT_BY_PURPOSE[name]
        for name in ("encrypt", "sign")
        if able[name] and name in wanted
    )
    return Posture(
        algorithm=algorithm,
        key_size=key_size,
        quantum_vulnerable=True,
        post_quantum=False,
        deprecated_from=deprecated,
        disallowed_from=NIST_DISALLOWED_FROM,
        replacements=replacements,
        rationale=rationale,
    )


def purposes(algorithm: str) -> dict[str, bool]:
    """Report what an algorithm can be used for in this library.

    Args:
        algorithm: Algorithm name.

    Returns:
        A mapping with ``encrypt`` and ``sign`` keys.

    Example:
        >>> purposes("x25519")
        {'encrypt': True, 'sign': False}
    """
    return {
        "encrypt": algorithm in _KEY_ESTABLISHMENT,
        "sign": algorithm in _SIGNATURE,
    }


def inventory() -> dict[str, dict[str, object]]:
    """Return the posture of every supported algorithm, keyed by name.

    Intended for a cryptographic inventory process that wants the whole
    table in one call rather than one assessment at a time.

    Example:
        >>> inventory()["rsa"]["quantum_vulnerable"]
        True
    """
    table: dict[str, dict[str, object]] = {}
    for name in SUPPORTED_ALGORITHMS:
        entry = assess(name).as_dict()
        entry["purposes"] = purposes(name)
        table[name] = entry
    return table


#: Algorithms this module can assess, for callers that want to check before
#: asking. ``test_policy.py`` asserts this stays in step with the generator
#: and that every vulnerable algorithm has a replacement; a module-level
#: assertion would be stripped by ``python -O`` and so cannot be relied on.
ASSESSABLE: Final = frozenset(SUPPORTED_ALGORITHMS)
