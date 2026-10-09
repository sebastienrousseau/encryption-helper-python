# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Finding cryptographic material on disk and reporting its migration status.

Before a post-quantum migration can be planned it has to be scoped, and
scoping means answering a question about files that already exist: which of
these keys, certificates and encrypted files use an algorithm that stops
being acceptable, and when. :func:`scan` answers it for a directory tree.

What this module reads
----------------------

Each candidate file is classified from its own contents rather than its
name, because key material is routinely stored with no extension or a local
convention. Recognised forms are PEM and DER public keys, PEM and DER
private keys, PEM and DER X.509 certificates, OpenSSH public keys, and
containers produced by this library.

What this module will not do
----------------------------

* It never asks for, reads or accepts a passphrase. An encrypted private key
  is reported as present but undetermined: the algorithm is inside the
  encrypted structure, and the honest answer is that it cannot be read
  without the passphrase. A scan is not a reason to handle secrets.
* It never follows a symbolic link, so a link planted in a scanned tree
  cannot redirect the scan outside it or create a traversal loop.
* It reads only regular files, so a named pipe in the tree cannot block the
  scan indefinitely.
* It reads at most :data:`MAX_CANDIDATE_BYTES` from any one file, so a large
  file that happens to begin like a certificate cannot exhaust memory.
* It records paths, algorithms and sizes. It does not record key material,
  and public keys are not retained after assessment.

Example:
    >>> import tempfile, pathlib
    >>> from encryption_helper import generate, encode_public_key
    >>> d = pathlib.Path(tempfile.mkdtemp())
    >>> key = generate("ed25519")
    >>> _ = (d / "signing.pub").write_bytes(encode_public_key(key.public_key()))
    >>> findings = scan([d])
    >>> findings[0].algorithm
    'ed25519'
    >>> findings[0].action_required
    True
    >>> findings[0].replacement
    'mldsa'
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    ed448,
    ed25519,
    mldsa,
    mlkem,
    rsa,
    x448,
    x25519,
)
from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes

from .crypto import metadata
from .policy import NIST_LEGACY_DISALLOWED_FROM, assess

__all__ = [
    "MAX_CANDIDATE_BYTES",
    "Finding",
    "classify",
    "scan",
    "summarise",
]

#: Most bytes read from any single file. A PEM certificate chain is a few
#: kilobytes; anything beyond this is not key material, and reading it would
#: turn a scan of a data directory into an out-of-memory event.
MAX_CANDIDATE_BYTES: Final = 64 * 1024

#: Kinds a finding can take. Reported as strings so a consumer in another
#: language does not need this module's enumeration.
KIND_PUBLIC_KEY: Final = "public-key"
KIND_PRIVATE_KEY: Final = "private-key"
KIND_ENCRYPTED_PRIVATE_KEY: Final = "encrypted-private-key"
KIND_CERTIFICATE: Final = "certificate"
KIND_CONTAINER: Final = "container"

#: PEM banners that indicate a private key protected by a passphrase.
_ENCRYPTED_BANNERS: Final = (
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"Proc-Type: 4,ENCRYPTED",
)

#: PEM banners that indicate an unprotected private key.
_PRIVATE_BANNERS: Final = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
)

#: Algorithm name and size by public key class, for every fixed-size type.
#: RSA and ECDSA are absent because they carry their size on the instance and
#: are asked directly.
_PUBLIC_KEY_NAMES: Final = (
    (ed25519.Ed25519PublicKey, "ed25519", 256),
    (ed448.Ed448PublicKey, "ed448", 448),
    (x25519.X25519PublicKey, "x25519", 256),
    (x448.X448PublicKey, "x448", 448),
    (mlkem.MLKEM768PublicKey, "mlkem", 768),
    (mlkem.MLKEM1024PublicKey, "mlkem", 1024),
    (mldsa.MLDSA44PublicKey, "mldsa", 44),
    (mldsa.MLDSA65PublicKey, "mldsa", 65),
    (mldsa.MLDSA87PublicKey, "mldsa", 87),
)


@dataclass(frozen=True)
class Finding:
    """One piece of cryptographic material and where it stands.

    Attributes:
        path: The file the material was found in.
        kind: One of the ``KIND_*`` values in this module.
        algorithm: Algorithm name, or :data:`None` where it could not be
            determined -- an encrypted private key, or a key type this
            library does not recognise.
        key_size: RSA modulus, curve size, or post-quantum parameter set.
            :data:`None` where not applicable or not determined.
        quantum_vulnerable: Whether the material is broken by a
            cryptanalytically relevant quantum computer. :data:`None` where
            the algorithm could not be determined.
        deprecated_from: Year from which NIST IR 8547 deprecates this
            choice, or :data:`None`.
        disallowed_from: Year from which NIST IR 8547 disallows it, or
            :data:`None`.
        replacements: Algorithms to migrate to, empty if no migration is
            needed. Two entries means the key can both encrypt and sign, as
            RSA can, and the correct successor depends on which it is used
            for -- a scan cannot tell from the key alone.
        detail: One sentence suitable for quoting in a report.
        subject: Certificate subject, or :data:`None` for anything else.
            Included because a certificate is usually identified by subject
            rather than by filename.
    """

    path: Path
    kind: str
    algorithm: str | None
    key_size: int | None
    quantum_vulnerable: bool | None
    deprecated_from: int | None
    disallowed_from: int | None
    replacements: tuple[str, ...]
    detail: str
    subject: str | None = None

    @property
    def action_required(self) -> bool:
        """Whether this finding needs a migration before the prohibition."""
        return bool(self.replacements)

    @property
    def replacement(self) -> str | None:
        """The single successor algorithm, if there is exactly one."""
        if len(self.replacements) == 1:
            return self.replacements[0]
        return None

    @property
    def undetermined(self) -> bool:
        """Whether the algorithm could not be established.

        An undetermined finding is not a clean result. It means the file
        needs a human, and a report should say so rather than omit it.
        """
        return self.algorithm is None

    @property
    def needs_attention(self) -> bool:
        """Whether this finding should stop a migration-readiness gate.

        Deliberately broader than :attr:`action_required`. An encrypted
        private key reports ``action_required`` as false only because its
        algorithm could not be read -- not because it was found acceptable.
        Treating that as a pass would let an RSA-2048 key through a gate for
        the sole reason that it was well protected, which is the wrong
        conclusion to draw from a passphrase.
        """
        return self.action_required or self.undetermined

    def as_dict(self) -> dict[str, object]:
        """Return the finding as a JSON-serialisable mapping."""
        return {
            "path": str(self.path),
            "kind": self.kind,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "quantum_vulnerable": self.quantum_vulnerable,
            "deprecated_from": self.deprecated_from,
            "disallowed_from": self.disallowed_from,
            "replacement": self.replacement,
            "replacements": list(self.replacements),
            "action_required": self.action_required,
            "undetermined": self.undetermined,
            "needs_attention": self.needs_attention,
            "detail": self.detail,
            "subject": self.subject,
        }


def _describe_public_key(key: PublicKeyTypes) -> tuple[str | None, int | None]:
    """Return the algorithm name and size for a public key.

    Mirrors :func:`~encryption_helper.keys.store.describe_key` for the public
    half, which is what a scan has: a certificate or a ``.pub`` file never
    carries the private key.

    Returns:
        An ``(algorithm, size)`` pair, or ``(None, None)`` for a key type
        this library does not assess.
    """
    if isinstance(key, rsa.RSAPublicKey):
        return "rsa", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        return "ecdsa", key.curve.key_size
    for cls, name, size in _PUBLIC_KEY_NAMES:
        if isinstance(key, cls):
            return name, size
    return None, None


def _from_public_key(
    path: Path, key: PublicKeyTypes, *, kind: str, subject: str | None = None
) -> Finding:
    """Build a finding by assessing a loaded public key."""
    algorithm, key_size = _describe_public_key(key)
    if algorithm is None:
        return Finding(
            path=path,
            kind=kind,
            algorithm=None,
            key_size=None,
            quantum_vulnerable=None,
            deprecated_from=None,
            disallowed_from=None,
            replacements=(),
            detail=(
                f"The key type {type(key).__name__} is not one this library "
                "assesses. Review it manually."
            ),
            subject=subject,
        )
    posture = assess(algorithm, key_size=key_size)
    return Finding(
        path=path,
        kind=kind,
        algorithm=algorithm,
        key_size=key_size,
        quantum_vulnerable=posture.quantum_vulnerable,
        deprecated_from=posture.deprecated_from,
        disallowed_from=posture.disallowed_from,
        replacements=posture.replacements,
        detail=posture.rationale,
        subject=subject,
    )


def _try_certificate(path: Path, blob: bytes) -> Finding | None:
    """Classify ``blob`` as an X.509 certificate, or return None."""
    for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            cert = loader(blob)
        except (ValueError, TypeError):
            continue
        return _from_public_key(
            path,
            cert.public_key(),
            kind=KIND_CERTIFICATE,
            subject=cert.subject.rfc4514_string(),
        )
    return None


def _try_public_key(path: Path, blob: bytes) -> Finding | None:
    """Classify ``blob`` as a public key, or return None."""
    loaders = (
        serialization.load_pem_public_key,
        serialization.load_der_public_key,
        serialization.load_ssh_public_key,
    )
    for loader in loaders:
        try:
            key = loader(blob)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            continue
        return _from_public_key(path, key, kind=KIND_PUBLIC_KEY)
    return None


def _try_private_key(path: Path, blob: bytes) -> Finding | None:
    """Classify ``blob`` as a private key, encrypted or not."""
    if any(banner in blob for banner in _ENCRYPTED_BANNERS):
        return Finding(
            path=path,
            kind=KIND_ENCRYPTED_PRIVATE_KEY,
            algorithm=None,
            key_size=None,
            quantum_vulnerable=None,
            deprecated_from=None,
            disallowed_from=None,
            replacements=(),
            detail=(
                "The private key is protected by a passphrase. Its algorithm "
                "is inside the encrypted structure and cannot be determined "
                "without the passphrase, which this scan does not request. "
                "Assess the matching public key, or record this file as "
                "requiring manual review."
            ),
        )
    if not any(banner in blob for banner in _PRIVATE_BANNERS):
        return None
    try:
        key = serialization.load_pem_private_key(blob, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return Finding(
            path=path,
            kind=KIND_PRIVATE_KEY,
            algorithm=None,
            key_size=None,
            quantum_vulnerable=None,
            deprecated_from=None,
            disallowed_from=None,
            replacements=(),
            detail=(
                "The file carries a private key banner but could not be "
                "parsed. Review it manually."
            ),
        )
    return _from_public_key(path, key.public_key(), kind=KIND_PRIVATE_KEY)


def _try_container(path: Path, blob: bytes) -> Finding | None:
    """Classify ``blob`` as a container produced by this library."""
    if not metadata.is_container(blob):
        return None
    info = metadata.describe_container(blob)
    name = info.key_establishment or f"identifier {info.key_establishment_id}"
    if not info.quantum_vulnerable:
        detail = (
            f"Encrypted file using {name}, a NIST post-quantum standard. "
            "No migration is required."
        )
        replacements: tuple[str, ...] = ()
    else:
        detail = (
            f"Encrypted file using {name}. Data recorded now can be "
            "decrypted once a cryptanalytically relevant quantum computer "
            "exists, so re-encryption is required if its confidentiality "
            "must outlast that point."
        )
        replacements = ("mlkem",)
    return Finding(
        path=path,
        kind=KIND_CONTAINER,
        algorithm=info.key_establishment,
        key_size=None,
        quantum_vulnerable=info.quantum_vulnerable,
        deprecated_from=None,
        disallowed_from=None,
        replacements=replacements,
        detail=detail,
    )


def classify(path: Path) -> Finding | None:
    """Identify the cryptographic material in one file, if any.

    Classification is by content, not by filename. A file that is not
    recognised yields :data:`None` rather than a finding, because a scan of a
    working directory would otherwise be mostly noise.

    Args:
        path: Regular file to examine.

    Returns:
        A :class:`Finding`, or :data:`None` if the file holds no recognised
        cryptographic material or cannot be read.

    Example:
        >>> import tempfile, pathlib
        >>> p = pathlib.Path(tempfile.mkstemp()[1])
        >>> _ = p.write_text("just some notes")
        >>> classify(p) is None
        True
    """
    try:
        with path.open("rb") as handle:
            blob = handle.read(MAX_CANDIDATE_BYTES)
    except OSError:
        # Unreadable files are the norm in a real tree. A scan reports what
        # it can see rather than failing on the first permission error.
        return None

    for attempt in (_try_container, _try_private_key, _try_certificate):
        finding = attempt(path, blob)
        if finding is not None:
            return finding
    return _try_public_key(path, blob)


def _walk(root: Path) -> Iterator[Path]:
    """Yield regular files under ``root``, never following a symbolic link.

    ``follow_symlinks=False`` on the directory check is what keeps a link to
    ``/`` from turning a scan of one directory into a scan of the filesystem.
    """
    if root.is_file() and not root.is_symlink():
        yield root
        return
    for current, directories, files in os.walk(root, followlinks=False):
        here = Path(current)
        # Prune symlinked directories: os.walk would otherwise descend into
        # them when followlinks is False only for the top level.
        directories[:] = [d for d in directories if not (here / d).is_symlink()]
        for name in files:
            candidate = here / name
            if candidate.is_symlink() or not candidate.is_file():
                continue
            yield candidate


def scan(paths: Iterable[str | os.PathLike[str]]) -> list[Finding]:
    """Scan files and directory trees for cryptographic material.

    Args:
        paths: Files or directories to examine. Directories are walked
            recursively without following symbolic links.

    Returns:
        Findings, ordered by path so two runs over an unchanged tree produce
        identical output and a diff is meaningful.

    Example:
        >>> scan([])
        []
    """
    findings: list[Finding] = []
    for entry in paths:
        root = Path(entry).expanduser()
        for candidate in _walk(root):
            finding = classify(candidate)
            if finding is not None:
                findings.append(finding)
    return sorted(findings, key=lambda f: str(f.path))


def summarise(findings: list[Finding]) -> dict[str, object]:
    """Reduce findings to the counts a report leads with.

    Args:
        findings: Findings from :func:`scan`.

    Returns:
        A JSON-serialisable summary.

    Example:
        >>> summarise([])["action_required"]
        0
    """
    by_kind: dict[str, int] = {}
    for finding in findings:
        by_kind[finding.kind] = by_kind.get(finding.kind, 0) + 1
    return {
        "examined": len(findings),
        "action_required": sum(1 for f in findings if f.action_required),
        "quantum_vulnerable": sum(1 for f in findings if f.quantum_vulnerable),
        "undetermined": sum(1 for f in findings if f.undetermined),
        "below_minimum_strength": sum(
            1
            for f in findings
            if f.disallowed_from is not None
            and f.disallowed_from <= NIST_LEGACY_DISALLOWED_FROM
        ),
        "needs_attention": sum(1 for f in findings if f.needs_attention),
        "by_kind": dict(sorted(by_kind.items())),
    }
