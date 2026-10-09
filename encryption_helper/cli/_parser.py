# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Argument parser construction."""

from __future__ import annotations

import argparse
import logging
from typing import TYPE_CHECKING

from ..crypto.streaming import DEFAULT_SEGMENT_SIZE
from ..keys import (
    ALLOWED_RSA_KEY_SIZES,
    DEFAULT_MLDSA_LEVEL,
    DEFAULT_MLKEM_LEVEL,
    DEFAULT_RSA_KEY_SIZE,
    SUPPORTED_ALGORITHMS,
    SUPPORTED_CURVES,
    SUPPORTED_MLDSA_LEVELS,
    SUPPORTED_MLKEM_LEVELS,
)
from ._commands import (
    _cmd_capabilities,
    _cmd_convert,
    _cmd_decrypt,
    _cmd_encrypt,
    _cmd_fingerprint,
    _cmd_inspect,
    _cmd_keygen,
    _cmd_scan,
    _cmd_sign,
    _cmd_verify,
)
from ._constants import _LOG_LEVELS, _STDIO, DEFAULT_MAX_INPUT_BYTES
from ._output import _VersionAction

logger = logging.getLogger(__name__)


def _add_passphrase_flags(
    parser: argparse.ArgumentParser, *, allow_opt_out: bool = False
) -> None:
    """Add the passphrase source flags as one mutually exclusive group.

    Exclusivity is enforced by the parser rather than by precedence rules
    later on. ``--no-passphrase --passphrase-file secret.txt`` is a
    contradiction, and argparse rejects it with a usage error instead of some
    branch quietly picking a winner -- which previously discarded the supplied
    passphrase and wrote an unencrypted key.

    Args:
        parser: Sub-parser to add the flags to.
        allow_opt_out: Whether ``--no-passphrase`` applies. It only makes
            sense when creating a key, not when reading an existing one.
    """
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--passphrase-env",
        metavar="VAR",
        help=(
            "Read the passphrase from this environment variable. Preferred "
            "over --passphrase-file in containers and CI."
        ),
    )
    group.add_argument(
        "--passphrase-file",
        metavar="PATH",
        help=(
            "Read the passphrase from this file. Exactly one trailing newline "
            "is removed; no other whitespace is stripped, so a passphrase may "
            "begin or end with a space. Keep the file mode 0600."
        ),
    )
    if allow_opt_out:
        group.add_argument(
            "--no-passphrase",
            action="store_true",
            help=(
                "Store the private key unencrypted. Required to skip "
                "passphrase protection: without it, a passphrase is prompted "
                "for, or must be supplied via --passphrase-env or "
                "--passphrase-file."
            ),
        )


def _add_io_flags(parser: argparse.ArgumentParser, *, output: bool = True) -> None:
    """Add the shared ``--in``/``--out`` flags."""
    parser.add_argument(
        "--progress",
        action="store_true",
        help=(
            "Report progress on stderr while streaming. Shows a percentage "
            "and ETA when the input size is known. Suppressed by --quiet."
        ),
    )
    parser.add_argument(
        "--segment-size",
        type=int,
        default=DEFAULT_SEGMENT_SIZE,
        metavar="BYTES",
        help=(
            f"Plaintext bytes per encrypted segment (default: "
            f"{DEFAULT_SEGMENT_SIZE // 1024} KiB). Bounds peak memory "
            "regardless of input size."
        ),
    )
    parser.add_argument(
        "--max-size",
        type=int,
        default=DEFAULT_MAX_INPUT_BYTES,
        metavar="BYTES",
        help=(
            f"Refuse non-streamed input larger than this (default: "
            f"{DEFAULT_MAX_INPUT_BYTES // (1024 * 1024)} MiB). Only applies "
            "where the whole input must be buffered -- reading a one-shot "
            "container, or from a pipe. File streaming is unbounded."
        ),
    )
    parser.add_argument(
        "--in",
        dest="input",
        default=_STDIO,
        metavar="PATH",
        help="Input file, or - for stdin (default: stdin).",
    )
    if output:
        parser.add_argument(
            "--out",
            dest="output",
            default=_STDIO,
            metavar="PATH",
            help="Output file, or - for stdout (default: stdout).",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Overwrite the output file if it exists, backing it up first.",
        )


if TYPE_CHECKING:
    # argparse publishes no name for the subparsers action, and the
    # private one is generic only to the type checker -- subscripting it
    # at runtime raises TypeError. Aliasing it here keeps the annotation
    # precise in all ten builders without a runtime cost, because
    # `from __future__ import annotations` leaves them unevaluated.
    _SubParsers = argparse._SubParsersAction[argparse.ArgumentParser]


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser for the whole command tree.

    Returns:
        The configured parser.
    """
    parser = argparse.ArgumentParser(
        prog="encryption-helper",
        description=(
            "Generate, protect and use asymmetric key pairs. Private keys are "
            "written owner-only and are never printed."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  encryption-helper keygen --out-dir ./secrets --name service\n"
            "  encryption-helper keygen --algorithm ed25519 "
            "--passphrase-env KEY_PASS\n"
            "  encryption-helper encrypt --public-key service.pub.pem "
            "--in secret.txt --out secret.bin\n"
            "  cat secret.bin | encryption-helper decrypt "
            "--private-key service.pem --in -\n"
        ),
    )
    parser.add_argument(
        "--version", action=_VersionAction, nargs=0, help="Print the version and exit."
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase log verbosity. Repeat for debug output.",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", help="Suppress non-error output."
    )
    parser.add_argument(
        "--log-level",
        choices=_LOG_LEVELS,
        help="Set an explicit log level, overriding -v and -q.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON on stdout instead of human text.",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND", required=True)

    _add_keygen(sub)
    _add_encrypt(sub)
    _add_decrypt(sub)
    _add_sign(sub)
    _add_verify(sub)
    _add_fingerprint(sub)
    _add_capabilities(sub)
    _add_inspect(sub)
    _add_scan(sub)
    _add_convert(sub)

    return parser


def _add_keygen(sub: _SubParsers) -> None:
    """Generate a key pair."""
    keygen = sub.add_parser(
        "keygen",
        help="Generate a key pair.",
        description="Generate a key pair and write it to disk.",
    )
    keygen.add_argument(
        "--algorithm",
        choices=SUPPORTED_ALGORITHMS,
        default="rsa",
        help=(
            "Key algorithm (default: rsa). Encryption: rsa, x25519, mlkem. "
            "Signing: rsa, ed25519, ed448, ecdsa, mldsa. Only mlkem and mldsa "
            "are post-quantum; see `encryption-helper capabilities`."
        ),
    )
    keygen.add_argument(
        "--key-size",
        type=int,
        choices=ALLOWED_RSA_KEY_SIZES,
        default=DEFAULT_RSA_KEY_SIZE,
        metavar="BITS",
        help=(
            f"RSA modulus size in bits, one of "
            f"{', '.join(str(s) for s in ALLOWED_RSA_KEY_SIZES)} "
            f"(default: {DEFAULT_RSA_KEY_SIZE}). Ignored for non-RSA "
            "algorithms."
        ),
    )
    keygen.add_argument(
        "--level",
        type=int,
        default=0,
        metavar="N",
        help=(
            "ML-KEM or ML-DSA parameter set. ML-KEM: "
            f"{', '.join(str(n) for n in sorted(SUPPORTED_MLKEM_LEVELS))} "
            f"(default {DEFAULT_MLKEM_LEVEL}). ML-DSA: "
            f"{', '.join(str(n) for n in sorted(SUPPORTED_MLDSA_LEVELS))} "
            f"(default {DEFAULT_MLDSA_LEVEL}). Ignored for other algorithms."
        ),
    )
    keygen.add_argument(
        "--curve",
        choices=sorted(SUPPORTED_CURVES),
        default="p256",
        help="ECDSA curve (default: p256). Ignored for other algorithms.",
    )
    keygen.add_argument(
        "--out-dir",
        default=".",
        metavar="DIR",
        help="Directory to write the key pair into (default: current directory).",
    )
    keygen.add_argument(
        "--name", default="key", metavar="STEM", help="Filename stem (default: key)."
    )
    keygen.add_argument(
        "--format",
        choices=("pem", "der", "openssh"),
        default="pem",
        help="Output encoding (default: pem).",
    )
    keygen.add_argument(
        "--force",
        action="store_true",
        help=(
            "Replace existing key files. The old files are backed up to "
            "timestamped siblings first."
        ),
    )
    keygen.add_argument(
        "--show-public",
        action="store_true",
        help="Also write the public key to stdout. The private key is never printed.",
    )
    _add_passphrase_flags(keygen, allow_opt_out=True)
    keygen.set_defaults(func=_cmd_keygen)


def _add_encrypt(sub: _SubParsers) -> None:
    """Encrypt data."""
    enc = sub.add_parser(
        "encrypt",
        help="Encrypt data to a public key.",
        description=(
            "Encrypt data using hybrid encryption: AES-256-GCM under a random "
            "content key wrapped with RSA-OAEP-SHA256."
        ),
    )
    enc.add_argument("--public-key", required=True, metavar="PATH")
    _add_io_flags(enc)
    enc.set_defaults(func=_cmd_encrypt)


def _add_decrypt(sub: _SubParsers) -> None:
    """Decrypt a container."""
    dec = sub.add_parser(
        "decrypt",
        help="Decrypt data with a private key.",
        description="Decrypt a container produced by `encryption-helper encrypt`.",
    )
    dec.add_argument("--private-key", required=True, metavar="PATH")
    _add_io_flags(dec)
    _add_passphrase_flags(dec)
    dec.set_defaults(func=_cmd_decrypt)


def _add_sign(sub: _SubParsers) -> None:
    """Sign data."""
    sgn = sub.add_parser(
        "sign",
        help="Sign data with a private key.",
        description="Sign data. RSA uses PSS with SHA-256.",
    )
    sgn.add_argument("--private-key", required=True, metavar="PATH")
    _add_io_flags(sgn)
    _add_passphrase_flags(sgn)
    sgn.set_defaults(func=_cmd_sign)


def _add_verify(sub: _SubParsers) -> None:
    """Verify a signature."""
    vfy = sub.add_parser(
        "verify",
        help="Verify a signature.",
        description="Verify a signature over data. Exits 4 if it does not verify.",
    )
    vfy.add_argument("--public-key", required=True, metavar="PATH")
    vfy.add_argument("--signature", required=True, metavar="PATH")
    _add_io_flags(vfy, output=False)
    vfy.set_defaults(func=_cmd_verify)


def _add_fingerprint(sub: _SubParsers) -> None:
    """Print a key fingerprint."""
    fpr = sub.add_parser(
        "fingerprint",
        help="Print a public key fingerprint.",
        description=(
            "Print the SHA-256 fingerprint of a public key, in the same form "
            "as `ssh-keygen -lf`."
        ),
    )
    fpr.add_argument("key", metavar="PATH")
    fpr.set_defaults(func=_cmd_fingerprint)


def _add_capabilities(sub: _SubParsers) -> None:
    """Report what this build supports."""
    caps = sub.add_parser(
        "capabilities",
        help="Report supported algorithms and their post-quantum status.",
        description=(
            "List every algorithm this build supports, whether it can encrypt "
            "or sign, and whether it is affected by the NIST IR 8547 "
            "deprecation horizon. Use --json for a cryptographic inventory."
        ),
    )
    caps.set_defaults(func=_cmd_capabilities)


def _add_inspect(sub: _SubParsers) -> None:
    """Describe a container without decrypting it."""
    insp = sub.add_parser(
        "inspect",
        help="Report a container's algorithms without decrypting it.",
        description=(
            "Report which algorithms protect an encrypted file, reading only "
            "its header. No private key is required and no plaintext is "
            "recovered, so this can be run by someone who is not entitled to "
            "the contents."
        ),
    )
    _add_io_flags(insp, output=False)
    insp.set_defaults(func=_cmd_inspect)


def _add_scan(sub: _SubParsers) -> None:
    """Inventory cryptographic material on disk."""
    scn = sub.add_parser(
        "scan",
        help="Report cryptographic material on disk and its migration status.",
        description=(
            "Examine files and directory trees for keys, certificates and "
            "encrypted files, and report which use quantum-vulnerable "
            "algorithms: those NIST IR 8547 (initial public draft) disallows "
            "after 2035, deprecating 112-bit keys such as RSA-2048 after "
            "2030. Keys below 112-bit strength, such as RSA-1024, are "
            "flagged as already disallowed.\n\n"
            "Classification is by file contents, not by filename. Symbolic "
            "links are not followed and no passphrase is requested, so an "
            "encrypted private key is reported as needing manual review "
            "rather than being unlocked."
        ),
    )
    scn.add_argument(
        "paths",
        nargs="+",
        metavar="PATH",
        help="Files or directories to examine. Directories are walked.",
    )
    scn.add_argument(
        "--fail-on-finding",
        action="store_true",
        help=(
            "Exit non-zero if anything needs migration or manual review, so "
            "the scan can gate a pipeline. Off by default, because reporting "
            "an inventory is not itself a failure."
        ),
    )
    scn.set_defaults(func=_cmd_scan)


def _add_convert(sub: _SubParsers) -> None:
    """Convert a key between encodings."""
    cvt = sub.add_parser(
        "convert",
        help="Convert a key between encodings.",
        description="Convert a key between PEM, DER and OpenSSH encodings.",
    )
    cvt.add_argument("--to", choices=("pem", "der", "openssh"), required=True)
    cvt.add_argument(
        "--private",
        action="store_true",
        help=(
            "Treat the input as a private key. The output is written "
            "owner-only and unencrypted, so redirect it carefully."
        ),
    )
    _add_io_flags(cvt)
    _add_passphrase_flags(cvt)
    cvt.set_defaults(func=_cmd_convert)
