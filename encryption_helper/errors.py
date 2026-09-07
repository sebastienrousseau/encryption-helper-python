"""Exception hierarchy for the :mod:`encryption_helper` package.

Every error raised deliberately by this package derives from
:class:`EncryptionHelperError`, so callers can catch the whole family with a
single ``except`` clause without also swallowing unrelated failures.

None of these exceptions ever carry private key material, passphrases, or
plaintext in their message. Error strings are safe to log.
"""

from __future__ import annotations

__all__ = [
    "DecryptionError",
    "EncryptionHelperError",
    "InvalidArgumentError",
    "KeyExistsError",
    "KeyGenerationError",
    "KeyReadError",
    "KeyWriteError",
    "SignatureVerificationError",
    "UnsupportedAlgorithmError",
]


class EncryptionHelperError(Exception):
    """Base class for every error raised by :mod:`encryption_helper`."""


class InvalidArgumentError(EncryptionHelperError, ValueError):
    """An argument was missing, malformed, or outside its permitted range.

    Also derives from :class:`ValueError` so that code written against the
    usual Python conventions keeps working.
    """


class UnsupportedAlgorithmError(InvalidArgumentError):
    """The requested algorithm, curve, or key type is not supported."""


class KeyGenerationError(EncryptionHelperError):
    """A key pair could not be generated."""


class KeyExistsError(EncryptionHelperError):
    """The destination file already exists and overwriting was not requested.

    Raised instead of silently replacing key material, which is unrecoverable.
    """


class KeyWriteError(EncryptionHelperError):
    """Key material could not be written to disk."""


class KeyReadError(EncryptionHelperError):
    """Key material could not be read or parsed.

    Raised for a missing file, an unreadable file, a corrupt encoding, and a
    wrong or missing passphrase alike. The message never distinguishes a wrong
    passphrase from a corrupt file in a way that would help an attacker.
    """


class DecryptionError(EncryptionHelperError):
    """A ciphertext could not be decrypted or failed its integrity check.

    Raised for a malformed container, an unsupported container version, the
    wrong private key, and a tampered ciphertext alike. The plaintext is never
    returned when this is raised.
    """


class SignatureVerificationError(EncryptionHelperError):
    """A signature did not verify against the supplied public key and data."""
