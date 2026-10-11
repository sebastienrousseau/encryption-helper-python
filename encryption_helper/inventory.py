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
* It never follows a symbolic link found inside a scanned tree, so a planted
  link cannot redirect the scan outside it or create a traversal loop. A path
  you name is taken as given, whether or not it is itself a link.
* It reads only regular files, and opens each without blocking or following
  a link, so a named pipe -- even one swapped in during the scan -- cannot
  block it indefinitely.
* It never silently skips what it cannot read. A file or directory that
  cannot be opened becomes an ``unreadable`` finding, which counts as
  needing attention: a file that could not be assessed is not a clean one.
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
import stat
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
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)

from . import _platform
from .crypto import metadata
from .errors import InvalidArgumentError
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
KIND_UNREADABLE: Final = "unreadable"


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


_ENCRYPTED_DETAIL: Final = (
    "The private key is protected by a passphrase. Its algorithm is inside "
    "the encrypted structure and cannot be determined without the passphrase, "
    "which this scan does not request. Assess the matching public key, or "
    "record this file as requiring manual review."
)

#: First byte of every DER encoding this scan reads: an ASN.1 SEQUENCE.
_DER_SEQUENCE: Final = 0x30


class _Encrypted:
    """Marker: the blob is a private key, but a passphrase protects it."""


def _load_private(blob: bytes) -> PrivateKeyTypes | _Encrypted | None:
    """Load ``blob`` as a private key in any encoding this library writes.

    PEM and OpenSSH keys announce themselves with a banner; DER keys do not,
    so any blob that starts like DER is tried as one. That is how `scan`
    missed DER keys entirely, and reported OpenSSH keys -- which were tried
    with the PEM loader -- as unparseable.

    RSA validation is skipped. It costs about 77 ms per RSA-3072 key, which
    dominated a scan, and buys nothing here: only the public half's size is
    read, and no operation is performed with the key.

    Returns:
        The key; :class:`_Encrypted` if it is passphrase-protected; or
        :data:`None` if ``blob`` is not a private key.

    Raises:
        ValueError: If a banner says private key but the content does not
            parse, so the caller can report it for review.
    """
    if b"-----BEGIN OPENSSH PRIVATE KEY-----" in blob:
        try:
            return serialization.load_ssh_private_key(blob, password=None)
        except TypeError:
            return _Encrypted()
    if any(banner in blob for banner in _PRIVATE_BANNERS):
        return serialization.load_pem_private_key(
            blob, password=None, unsafe_skip_rsa_key_validation=True
        )
    return _load_der_private(blob)


def _load_der_private(blob: bytes) -> PrivateKeyTypes | _Encrypted | None:
    """Try ``blob`` as a DER private key, which carries no banner."""
    if not blob or blob[0] != _DER_SEQUENCE:
        return None
    try:
        return serialization.load_der_private_key(
            blob, password=None, unsafe_skip_rsa_key_validation=True
        )
    except TypeError:
        return _Encrypted()  # encrypted PKCS#8: a password is required
    except (ValueError, UnsupportedAlgorithm):
        return None  # DER, but not a private key: perhaps a certificate


def _private_finding(path: Path, kind: str, detail: str) -> Finding:
    return Finding(
        path=path,
        kind=kind,
        algorithm=None,
        key_size=None,
        quantum_vulnerable=None,
        deprecated_from=None,
        disallowed_from=None,
        replacements=(),
        detail=detail,
    )


def _try_private_key(path: Path, blob: bytes) -> Finding | None:
    """Classify ``blob`` as a private key, encrypted or not."""
    if any(banner in blob for banner in _ENCRYPTED_BANNERS):
        return _private_finding(path, KIND_ENCRYPTED_PRIVATE_KEY, _ENCRYPTED_DETAIL)
    try:
        key = _load_private(blob)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        return _private_finding(
            path,
            KIND_PRIVATE_KEY,
            "The file carries a private key banner but could not be parsed. "
            "Review it manually.",
        )
    if key is None:
        return None
    if isinstance(key, _Encrypted):
        return _private_finding(path, KIND_ENCRYPTED_PRIVATE_KEY, _ENCRYPTED_DETAIL)
    return _from_public_key(path, key.public_key(), kind=KIND_PRIVATE_KEY)


def _try_container(path: Path, blob: bytes) -> Finding | None:
    """Classify ``blob`` as a container produced by this library."""
    if not metadata.is_container(blob):
        return None
    try:
        info = metadata.describe_container(blob)
    except InvalidArgumentError:
        # The magic matched but the header is incomplete. That is one bad
        # file, not a reason to abandon the inventory: a single five-byte
        # file would otherwise end the scan of an entire tree.
        return Finding(
            path=path,
            kind=KIND_CONTAINER,
            algorithm=None,
            key_size=None,
            quantum_vulnerable=None,
            deprecated_from=None,
            disallowed_from=None,
            replacements=(),
            detail=(
                "Starts with the container magic number but the header is "
                "incomplete. Review it manually."
            ),
        )
    name = info.key_establishment or f"identifier {info.key_establishment_id}"
    replacements: tuple[str, ...] = ()
    if info.quantum_vulnerable is None:
        detail = (
            f"Encrypted file using unrecognised mechanism {name}. Its "
            "quantum resistance cannot be established; review it manually."
        )
    elif not info.quantum_vulnerable:
        detail = (
            f"Encrypted file using {name}, a NIST post-quantum standard. "
            "No migration is required."
        )
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
        cryptographic material or cannot be read. :func:`scan` reports an
        unreadable file instead of passing over it.

    Example:
        >>> import tempfile, pathlib
        >>> p = pathlib.Path(tempfile.mkstemp()[1])
        >>> _ = p.write_text("just some notes")
        >>> classify(p) is None
        True
    """
    try:
        return _classify(path)
    except OSError:
        return None


def _classify(path: Path) -> Finding | None:
    """:func:`classify`, letting a read failure propagate as ``OSError``."""
    # Non-blocking and no-follow: a FIFO or link swapped in after the walk
    # saw a regular file can neither stall the scan nor redirect it.
    with open(path, "rb", opener=_platform.safe_opener) as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return None  # Replaced by a FIFO or device since the walk saw it.
        blob = handle.read(MAX_CANDIDATE_BYTES)

    for attempt in (_try_container, _try_private_key, _try_certificate):
        finding = attempt(path, blob)
        if finding is not None:
            return finding
    return _try_public_key(path, blob)


def _unreadable(path: Path, error: OSError, *, directory: bool = False) -> Finding:
    """A finding for something the scan could not look inside."""
    reason = error.strerror or type(error).__name__
    what = "directory could not be listed" if directory else "file could not be read"
    return Finding(
        path=path,
        kind=KIND_UNREADABLE,
        algorithm=None,
        key_size=None,
        quantum_vulnerable=None,
        deprecated_from=None,
        disallowed_from=None,
        replacements=(),
        detail=(
            f"This {what} ({reason}), so whether it holds cryptographic "
            "material is unknown. Rerun with access to it, or review it "
            "manually."
        ),
    )


def _walk(root: Path, errors: list[Finding]) -> Iterator[Path]:
    """Yield regular files under ``root``, never following a symbolic link.

    Iterative, with an explicit stack: ``os.walk`` recurses on Python 3.10
    and 3.11, so a deep enough tree raised ``RecursionError`` and aborted the
    whole scan. ``root`` itself is taken as given even if it is a link --
    the caller named it -- but no link found beneath it is followed.

    Args:
        root: File or directory to examine.
        errors: Receives an ``unreadable`` finding for each directory that
            could not be listed.
    """
    if root.is_file():
        yield root
        return
    if not root.is_dir():
        return
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                children = sorted(entries, key=lambda entry: entry.name)
        except OSError as exc:
            errors.append(_unreadable(directory, exc, directory=True))
            continue
        for entry in reversed(children):
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                elif entry.is_file(follow_symlinks=False):
                    yield Path(entry.path)
            except OSError as exc:  # pragma: no cover - entry vanished or EIO
                errors.append(_unreadable(Path(entry.path), exc))


def scan(paths: Iterable[str | os.PathLike[str]]) -> list[Finding]:
    """Scan files and directory trees for cryptographic material.

    Args:
        paths: Files or directories to examine. Directories are walked
            recursively without following symbolic links.

    Returns:
        Findings, ordered by path so two runs over an unchanged tree produce
        identical output and a diff is meaningful. Includes an ``unreadable``
        finding for every file or directory that could not be read.

    Example:
        >>> scan([])
        []
    """
    findings: list[Finding] = []
    for entry in paths:
        root = Path(entry).expanduser()
        for candidate in _walk(root, findings):
            try:
                finding = _classify(candidate)
            except OSError as exc:
                finding = _unreadable(candidate, exc)
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
