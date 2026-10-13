# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Post-quantum migration policy, expressed as data rather than prose.

Organisations holding long-lived keys need to answer a specific question:
which of their keys stop being acceptable, and when. NIST IR 8547 sets the
dates, keyed on each key's classical security strength; this module turns
them into values a program can act on, so an inventory process does not have
to parse documentation or help text.

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
    "NIST_LEGACY_DISALLOWED_FROM",
    "REFERENCES",
    "VALIDATION_NOTE",
    "Posture",
    "assess",
    "horizon",
    "inventory",
    "purposes",
    "security_strength",
]

#: Transition year after which NIST IR 8547 deprecates public-key algorithms
#: providing 112-bit security strength -- RSA-2048, P-224 and their
#: equivalents. Deprecated means still permitted, but carrying risk that must
#: be accepted deliberately. Algorithms at 128 bits or more are *not*
#: deprecated on this date; they move straight to disallowed after
#: :data:`NIST_DISALLOWED_FROM`.
#:
#: Every year in this module is the year NIST names, and NIST's wording is
#: "after": use remains acceptable to the end of that year.
NIST_DEPRECATED_FROM: Final = 2030

#: Transition year after which NIST IR 8547 disallows every quantum-vulnerable
#: public-key algorithm covered here, whatever its classical strength.
NIST_DISALLOWED_FROM: Final = 2035

#: Transition year after which NIST SP 800-131A disallowed algorithms below
#: 112-bit security strength, such as RSA-1024 and P-192. A key of this
#: strength found by an inventory scan is not on a future deadline: it is
#: already outside NIST guidance.
NIST_LEGACY_DISALLOWED_FROM: Final = 2013

#: RSA modulus size below which NIST IR 8547 withdraws approval at the
#: earlier 2030 date rather than 2035, because its security strength is
#: 112 bits rather than 128.
MINIMUM_RSA_KEY_SIZE_AFTER_2030: Final = 3072

#: RSA modulus thresholds and their security strength (SP 800-57 Part 1,
#: Table 2), strongest first.
_RSA_STRENGTH: Final = ((15360, 256), (7680, 192), (3072, 128), (2048, 112))

#: Strength assigned to RSA below 2048 bits. RSA-1024 is about 80 bits.
_RSA_LEGACY_STRENGTH: Final = 80

#: Classical security strength, in bits, of the fixed-size algorithms.
#: Ed448 is 224; the others are 128 (SP 800-57 Part 1, SP 800-186).
_FIXED_STRENGTH: Final = {"ed25519": 128, "x25519": 128, "ed448": 224}

#: How each algorithm is written in prose a report may quote.
_DISPLAY_NAME: Final = {
    "ecdsa": "ECDSA",
    "ed25519": "Ed25519",
    "ed448": "Ed448",
    "x25519": "X25519",
}

#: The 112-bit boundary NIST's two transition steps turn on.
_STRENGTH_112: Final = 112

#: Publications the judgements in this module are taken from.
REFERENCES: Final = (
    "NIST IR 8547 (initial public draft), Transition to Post-Quantum "
    "Cryptography Standards",
    "NIST SP 800-131A Rev. 2, Transitioning the Use of Cryptographic "
    "Algorithms and Key Lengths",
    "NIST SP 800-57 Part 1 Rev. 5, Recommendation for Key Management",
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
        deprecated_from: Year after which use is deprecated, or :data:`None`
            if no deprecation step applies -- either because the algorithm
            is post-quantum, or because it moves straight to disallowed.
        disallowed_from: Year after which use is disallowed, or :data:`None`
            if no prohibition applies. A year in the past means the key is
            already outside NIST guidance.
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
        "legacy_disallowed_from": NIST_LEGACY_DISALLOWED_FROM,
        "minimum_rsa_key_size_after_2030": MINIMUM_RSA_KEY_SIZE_AFTER_2030,
        "references": list(REFERENCES),
        "validation_note": VALIDATION_NOTE,
    }


def security_strength(algorithm: str, key_size: int | None = None) -> int | None:
    """Return the classical security strength of a key, in bits.

    This is the figure NIST's transition dates are keyed on. It describes
    resistance to classical attack only; every algorithm with a value here is
    still broken by a cryptanalytically relevant quantum computer.

    Args:
        algorithm: Algorithm name.
        key_size: RSA modulus, or the curve's size in bits for ECDSA.

    Returns:
        The strength in bits, or :data:`None` where it depends on a size
        that was not supplied, or the algorithm is post-quantum.

    Example:
        >>> security_strength("rsa", 2048), security_strength("rsa", 3072)
        (112, 128)
        >>> security_strength("ecdsa", 256), security_strength("ed448")
        (128, 224)
        >>> security_strength("rsa", 1024)
        80
    """
    if algorithm in _FIXED_STRENGTH:
        return _FIXED_STRENGTH[algorithm]
    if key_size is None:
        return None
    if algorithm == "rsa":
        for modulus, bits in _RSA_STRENGTH:
            if key_size >= modulus:
                return bits
        return _RSA_LEGACY_STRENGTH
    if algorithm == "ecdsa":
        return key_size // 2
    return None


def _classical_dates(
    algorithm: str, key_size: int | None
) -> tuple[int | None, int, str]:
    """Return the deprecation year, prohibition year and the reason for them.

    The dates depend on security strength, not on the algorithm family:
    RSA-2048 and RSA-3072 are on different timetables, and so are P-224 and
    P-256. Where the strength cannot be established, RSA is reported on the
    earlier date, because a 2048-bit modulus is both permitted and common;
    the curves this library generates are all 128-bit or stronger.
    """
    if algorithm == "rsa":
        label = "RSA" if key_size is None else f"RSA-{key_size}"
    elif algorithm == "ecdsa" and key_size is not None:
        label = f"ECDSA on a {key_size}-bit curve"
    else:
        label = _DISPLAY_NAME.get(algorithm, algorithm)
    quantum = (
        "It would be broken by a cryptanalytically relevant quantum "
        "computer, which does not exist today."
    )
    strength = security_strength(algorithm, key_size)

    if strength is not None and strength < _STRENGTH_112:
        return (
            None,
            NIST_LEGACY_DISALLOWED_FROM,
            f"{label} provides {strength}-bit security strength, which NIST "
            "SP 800-131A has disallowed since the end of "
            f"{NIST_LEGACY_DISALLOWED_FROM}. Replace it now. {quantum}",
        )
    if strength == _STRENGTH_112 or (strength is None and algorithm == "rsa"):
        detail = (
            f"{label} provides 112-bit security strength"
            if strength is not None
            else "The modulus is unknown, so this is reported on the earlier "
            f"timetable: RSA below {MINIMUM_RSA_KEY_SIZE_AFTER_2030} bits provides "
            "112-bit security strength"
        )
        return (
            NIST_DEPRECATED_FROM,
            NIST_DISALLOWED_FROM,
            f"{detail}, which NIST IR 8547 (initial public draft) deprecates "
            f"after {NIST_DEPRECATED_FROM} and disallows after "
            f"{NIST_DISALLOWED_FROM}. {quantum}",
        )
    return (
        None,
        NIST_DISALLOWED_FROM,
        f"{label} would be broken by a cryptanalytically relevant quantum "
        "computer, which does not exist today. NIST IR 8547 (initial public "
        f"draft) disallows it after {NIST_DISALLOWED_FROM}.",
    )


def assess(
    algorithm: str, *, key_size: int | None = None, purpose: str | None = None
) -> Posture:
    """Report where an algorithm choice stands against the NIST timetable.

    Args:
        algorithm: Algorithm name, as :func:`~encryption_helper.generate`
            accepts it.
        key_size: Modulus size for RSA, curve size in bits for ECDSA, or
            parameter set for ML-KEM and ML-DSA. Optional, but it decides
            the dates for RSA and ECDSA, which depend on security strength.
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

    deprecated, disallowed, rationale = _classical_dates(algorithm, key_size)

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
        disallowed_from=disallowed,
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
