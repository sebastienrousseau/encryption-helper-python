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

import itertools
import logging
import os
import time
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    ec,
    rsa,
)
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)

from . import _io, _platform
from ._labels import KEY_TYPES
from .crypto import metadata
from .errors import InvalidArgumentError
from .policy import NIST_LEGACY_DISALLOWED_FROM, assess, horizon

__all__ = [
    "MAX_CANDIDATE_BYTES",
    "Finding",
    "build_report",
    "classify",
    "scan",
    "scan_report",
    "summarise",
]

_LOG = logging.getLogger(__name__)

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

#: Algorithm name and size by public key class, for every fixed-size type,
#: read from the package's one table so the scan cannot drift from what the
#: rest of the package calls a key. RSA and ECDSA are absent because they
#: carry their size on the instance and are asked directly.
_PUBLIC_KEY_NAMES: Final = tuple(
    (entry.public, entry.algorithm, entry.size) for entry in KEY_TYPES
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
        return _undetermined(
            path,
            kind,
            f"The key type {type(key).__name__} is not one this library "
            "assesses. Review it manually.",
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


def _undetermined(
    path: Path, kind: str, detail: str, *, subject: str | None = None
) -> Finding:
    """A finding whose algorithm could not be established: it needs a human."""
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
        subject=subject,
    )


def _try_certificate(path: Path, blob: bytes) -> Finding | None:
    """Classify ``blob`` as an X.509 certificate, or return None.

    Parsing a certificate does not load its key: ``public_key()`` does, and
    raises for a key type cryptography does not support. That call used to
    sit outside any handler, so one planted certificate raised out of
    :func:`scan` and suppressed the whole report. The certificate is now a
    finding of its own, undetermined, because a key the scan cannot name is
    exactly what a migration inventory must surface.
    """
    for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
        try:
            cert = loader(blob)
        except (ValueError, TypeError):
            continue
        try:
            subject: str | None = cert.subject.rfc4514_string()
        except ValueError:
            subject = None
        try:
            key = cert.public_key()
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            return _undetermined(
                path,
                KIND_CERTIFICATE,
                f"The certificate's key could not be loaded ({exc}). "
                "Review it manually.",
                subject=subject,
            )
        return _from_public_key(path, key, kind=KIND_CERTIFICATE, subject=subject)
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


def _classify(path: Path, expected: tuple[int, int] | None = None) -> Finding | None:
    """:func:`classify`, letting a read failure propagate as ``OSError``.

    Any other failure while interpreting the bytes becomes an ``unreadable``
    finding for this file. The parsers are cryptography's and this module's,
    and the next bug in either must cost one file, not the scan: the
    directories scanned are not vetted, and through the MCP server the scan
    runs at a model's request.
    """
    # Non-blocking and no-follow: a FIFO or link swapped in after the walk
    # saw a regular file can neither stall the scan nor redirect it, and the
    # identity the walk recorded must match what is opened.
    try:
        blob = _io._read_regular(
            path, MAX_CANDIDATE_BYTES, prefix=True, expected=expected
        )
    except _io.NotRegularFileError:
        return None  # Replaced by a FIFO or device since the walk saw it.

    try:
        for attempt in (_try_container, _try_private_key, _try_certificate):
            finding = attempt(path, blob)
            if finding is not None:
                return finding
        return _try_public_key(path, blob)
    except Exception as exc:  # noqa: BLE001 - hostile content must not end a scan
        _LOG.debug("could not classify %s", path, exc_info=True)
        return _not_examined(
            path,
            f"This file could not be classified ({type(exc).__name__}), so "
            "whether it holds cryptographic material is unknown. Review it "
            "manually.",
        )


def _not_examined(path: Path, detail: str) -> Finding:
    """An ``unreadable`` finding: something the scan could not look inside."""
    return _undetermined(path, KIND_UNREADABLE, detail)


def _unreadable(path: Path, error: OSError, *, directory: bool = False) -> Finding:
    """A finding for a file or directory a read failure kept the scan out of."""
    reason = error.strerror or type(error).__name__
    what = "directory could not be listed" if directory else "file could not be read"
    return _not_examined(
        path,
        f"This {what} ({reason}), so whether it holds cryptographic material "
        "is unknown. Rerun with access to it, or review it manually.",
    )


def _unexaminable_root(root: Path) -> Finding:
    """A finding for a root that is neither a file nor a directory.

    It used to yield nothing, so ``scan --fail-on-finding`` over a dangling
    link or a FIFO passed a gate having examined nothing.
    """
    if not os.path.lexists(root):
        reason = "does not exist"
    elif not root.exists():
        reason = "is a symbolic link to something that does not exist"
    else:
        reason = "is not a regular file or directory"
    return _not_examined(root, f"This path {reason}, so nothing under it was examined.")


class _Budget:
    """How much one scan may examine, and why it stopped if it did."""

    def __init__(self, max_entries: int | None, time_budget: float | None) -> None:
        self.max_entries = max_entries
        self.time_budget = time_budget
        self.deadline = None if time_budget is None else time.monotonic() + time_budget
        self.entries = 0
        self.stopped: str | None = None

    def remaining(self) -> int | None:
        """Entries still allowed, or None if unbounded."""
        if self.max_entries is None:
            return None
        return max(self.max_entries - self.entries, 0)

    def spend(self) -> bool:
        """Account for one more file or directory; False once exhausted."""
        if self.stopped is not None:
            return False
        if self.max_entries is not None and self.entries >= self.max_entries:
            self.stopped = (
                f"Stopped after examining {self.entries} entries (files and "
                "directories), the most this scan may examine. Narrow the path "
                "to examine the rest."
            )
            return False
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.stopped = (
                f"Stopped after {self.time_budget:g} seconds, the longest this "
                "scan may run. Narrow the path to examine the rest."
            )
            return False
        self.entries += 1
        return True


_Identity = tuple[int, int]


def _walk(
    root: Path, errors: list[Finding], budget: _Budget
) -> Iterator[tuple[Path, _Identity]]:
    """Yield regular files under ``root``, never following a symbolic link.

    Iterative, with an explicit stack: ``os.walk`` recurses on Python 3.10
    and 3.11, so a deep enough tree raised ``RecursionError`` and aborted the
    whole scan. ``root`` itself is taken as given even if it is a link --
    the caller named it -- but no link found beneath it is followed.

    Each file is yielded with the identity (device, inode) the walk saw, and
    each directory is listed only if it still has the identity it was found
    with, so replacing a directory -- or a parent -- with a link mid-scan
    cannot redirect the scan outside the tree. A directory is walked at most
    once by identity, so a bind mount or junction leading back into the tree
    costs one visit, not a loop.

    Args:
        root: File or directory to examine.
        errors: Receives an ``unreadable`` finding for each directory that
            could not be listed or had changed, and for a root that cannot be
            examined.
        budget: Bounds the walk. Each file or directory found spends one
            entry, and a listing is never read past what remains, so a
            directory of ten million entries is not materialised to examine
            ten.
    """
    if root.is_file():
        if budget.spend():
            yield root, _platform.identity_of(root.stat())
        return
    if not root.is_dir():
        errors.append(_unexaminable_root(root))
        return
    pending: list[tuple[Path, _Identity | None]] = [(root, None)]
    visited: set[_Identity] = set()
    while pending:
        directory, expected = pending.pop()
        is_root = expected is None
        try:
            with _platform.open_directory(
                directory, expected, follow=is_root
            ) as listing:
                children = _list(directory, listing, budget, errors)
        except OSError as exc:
            errors.append(_unreadable(directory, exc, directory=True))
            continue
        for path, kind, identity in reversed(children):
            if not budget.spend():
                return
            if kind == "file":
                yield path, identity
            elif identity not in visited:
                visited.add(identity)
                pending.append((path, identity))


def _list(
    directory: Path,
    listing: Iterator[os.DirEntry[str]],
    budget: _Budget,
    errors: list[Finding],
) -> list[tuple[Path, str, _Identity]]:
    """Read one listing into ``(path, kind, identity)``, sorted by name.

    Everything is asked of each entry here, while the directory is open: an
    entry listed through a descriptor answers through that descriptor.
    Entries that are neither directories nor regular files are dropped, as
    are links, which are never followed.
    """
    remaining = budget.remaining()
    entries = listing if remaining is None else itertools.islice(listing, remaining + 1)
    children: list[tuple[Path, str, _Identity]] = []
    for entry in entries:
        path = directory / entry.name
        try:
            if entry.is_dir(follow_symlinks=False):
                kind = "directory"
            elif entry.is_file(follow_symlinks=False):
                kind = "file"
            else:
                continue
            children.append((path, kind, _platform.entry_identity(entry, directory)))
        except OSError as exc:  # pragma: no cover - entry vanished or EIO
            errors.append(_unreadable(path, exc))
    return sorted(children, key=lambda child: child[0].name)


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
    return _scan(paths, _Budget(None, None))


def _scan(paths: Iterable[str | os.PathLike[str]], budget: _Budget) -> list[Finding]:
    """:func:`scan`, within ``budget``."""
    findings: list[Finding] = []
    for entry in paths:
        root = Path(entry).expanduser()
        for candidate, identity in _walk(root, findings, budget):
            try:
                finding = _classify(candidate, identity)
            except OSError as exc:
                finding = _unreadable(candidate, exc)
            if finding is not None:
                findings.append(finding)
    return sorted(findings, key=lambda f: str(f.path))


def scan_report(
    paths: Iterable[str | os.PathLike[str]],
    *,
    limit: int | None = None,
    max_entries: int | None = None,
    time_budget: float | None = None,
) -> dict[str, object]:
    """Scan, and return the report the CLI and the MCP server both emit.

    With no bounds the walk is complete and the report is exactly
    ``{"summary", "findings", "horizon"}``, the CLI's ``scan --json``
    contract. A caller serving untrusted requests should pass bounds: an
    unbounded walk's cost and response grow with whatever tree it is
    pointed at.

    Args:
        paths: Files or directories to examine, as for :func:`scan`.
        limit: Most findings to include. The summary always counts every
            finding; ``truncated`` says whether any were left out.
        max_entries: Most files and directories to examine. When reached,
            the walk stops and ``incomplete`` says why.
        time_budget: Most seconds to spend walking. Checked between entries;
            one file costs at most a :data:`MAX_CANDIDATE_BYTES` read.

    Returns:
        A JSON-serialisable report. ``truncated`` is present when ``limit``
        is given; ``incomplete`` only when a bound stopped the walk.

    Raises:
        InvalidArgumentError: If a bound is not positive.

    Example:
        >>> sorted(scan_report([]))
        ['findings', 'horizon', 'summary']
    """
    for name, value in (("limit", limit), ("max_entries", max_entries)):
        if value is not None and value < 1:
            msg = f"{name} must be at least 1, not {value}."
            raise InvalidArgumentError(msg)
    if time_budget is not None and time_budget <= 0:
        msg = f"time_budget must be positive, not {time_budget}."
        raise InvalidArgumentError(msg)
    budget = _Budget(max_entries, time_budget)
    findings = _scan(paths, budget)
    return build_report(findings, limit=limit, incomplete=budget.stopped)


def build_report(
    findings: list[Finding],
    *,
    limit: int | None = None,
    incomplete: str | None = None,
) -> dict[str, object]:
    """Build the scan report from findings already in hand.

    :func:`scan_report` is this over a fresh scan. A caller that also needs
    the :class:`Finding` objects -- the CLI renders them as a table --
    scans once and builds the report from the same findings.

    Args:
        findings: Findings from :func:`scan`.
        limit: Most findings to include; adds ``truncated``.
        incomplete: Why the scan stopped early, if it did; adds
            ``incomplete``.

    Returns:
        The JSON-serialisable report described in :func:`scan_report`.

    Example:
        >>> build_report([], limit=10)["truncated"]
        False
    """
    shown = findings if limit is None else findings[:limit]
    report: dict[str, object] = {
        "summary": summarise(findings),
        "findings": [finding.as_dict() for finding in shown],
        "horizon": horizon(),
    }
    if limit is not None:
        report["truncated"] = len(findings) > limit
    if incomplete is not None:
        report["incomplete"] = incomplete
    return report


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
