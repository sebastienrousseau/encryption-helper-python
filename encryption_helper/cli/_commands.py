# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""One function per subcommand.

Each takes the parsed arguments and returns a process exit code. The parser
in :mod:`._parser` decides which one runs.
"""

from __future__ import annotations

import argparse
import io
import logging
import sys
from typing import Any

from .._io import (
    PUBLIC_FILE_MODE,
    SECRET_FILE_MODE,
    read_bytes,
    resolve_destination,
)
from ..crypto import decrypt, sign, verify
from ..crypto.envelope import (
    AEAD_AES_256_GCM_STREAM,
    QUANTUM_VULNERABLE_KEMS,
    SUPPORTED_KEMS,
)
from ..crypto.streaming import decrypt_stream, encrypt_stream
from ..keys import (
    ALLOWED_RSA_KEY_SIZES,
    POST_QUANTUM,
    QUANTUM_VULNERABLE,
    SUPPORTED_ALGORITHMS,
    SUPPORTED_MLDSA_LEVELS,
    SUPPORTED_MLKEM_LEVELS,
    encode_private_key,
    encode_public_key,
    fingerprint_sha256,
    generate,
    load_public_key_file,
    write_key_pair,
)
from ._constants import (
    _AEAD_ID_OFFSET,
    _PEEK_SIZE,
    EXIT_OK,
)
from ._output import _emit
from ._passphrase import (
    _load_private_key,
    _new_key_passphrase,
)
from ._progress import _make_progress
from ._streams import (
    _input_stream,
    _is_streaming_container,
    _output_stream,
    _read_input,
    _write_output,
)
from ._warn import _warn_if_inside_git_worktree

logger = logging.getLogger(__name__)


def _resolve_runtime_version() -> str:
    """Read the package version, deferred to keep import cost down."""
    from .. import __version__  # noqa: PLC0415

    return str(__version__)


def _capabilities() -> dict[str, Any]:
    """Describe what this build can do, and what is on a deadline.

    Machine-readable so a cryptographic inventory tool can answer "where is
    our quantum-vulnerable material?" without parsing help text. NIST IR 8547
    deprecates the classical algorithms from 2030 and disallows them from
    2035, so the horizon is reported per algorithm rather than left implicit.
    """
    return {
        "version": _resolve_runtime_version(),
        "algorithms": {
            name: {
                "quantum_vulnerable": name in QUANTUM_VULNERABLE,
                "post_quantum": name in POST_QUANTUM,
                "deprecated_from": 2030 if name in QUANTUM_VULNERABLE else None,
                "disallowed_from": 2035 if name in QUANTUM_VULNERABLE else None,
                "can_encrypt": name in {"rsa", "x25519", "mlkem"},
                "can_sign": name in {"rsa", "ed25519", "ed448", "ecdsa", "mldsa"},
            }
            for name in SUPPORTED_ALGORITHMS
        },
        "rsa_key_sizes": list(ALLOWED_RSA_KEY_SIZES),
        "mlkem_levels": sorted(SUPPORTED_MLKEM_LEVELS),
        "mldsa_levels": sorted(SUPPORTED_MLDSA_LEVELS),
        "container_kems": sorted(SUPPORTED_KEMS),
        "quantum_vulnerable_kems": sorted(QUANTUM_VULNERABLE_KEMS),
        "formats": ["pem", "der", "openssh"],
        "standards": ["FIPS 203 (ML-KEM)", "FIPS 204 (ML-DSA)", "NIST IR 8547"],
    }


def _cmd_capabilities(args: argparse.Namespace) -> int:
    """Report supported algorithms and their post-quantum status."""
    caps = _capabilities()
    rows = [
        f"encryption-helper {caps['version']}",
        "",
        f"{'algorithm':<10} {'encrypt':>8} {'sign':>5} {'post-quantum':>13}  horizon",
        "-" * 58,
    ]
    for name, info in caps["algorithms"].items():
        horizon = (
            f"deprecated {info['deprecated_from']}, disallowed "
            f"{info['disallowed_from']}"
            if info["quantum_vulnerable"]
            else "no deadline"
        )
        rows.append(
            f"{name:<10} {'yes' if info['can_encrypt'] else '-':>8} "
            f"{'yes' if info['can_sign'] else '-':>5} "
            f"{'yes' if info['post_quantum'] else 'no':>13}  {horizon}"
        )
    rows += [
        "",
        "Horizons are from NIST IR 8547. Algorithms with a deadline should not",
        "be chosen for key material that must outlive it.",
    ]
    _emit(args, "\n".join(rows), caps)
    return EXIT_OK


def _warn_if_quantum_vulnerable(args: argparse.Namespace, algorithm: str) -> None:
    """Note the deprecation horizon when generating a classical key.

    Not a refusal: RSA and the curves remain correct, widely interoperable
    and the right choice for plenty of short-lived uses. But the dates are
    published, and a user choosing a default should know them.
    """
    if args.quiet or algorithm not in QUANTUM_VULNERABLE:
        return
    print(
        f"note: {algorithm} is broken by a quantum computer. NIST IR 8547 "
        "deprecates it from\n"
        "      2030 and disallows it from 2035. For key material that must "
        "outlive those\n"
        "      dates use --algorithm mlkem (encryption) or mldsa (signing).",
        file=sys.stderr,
    )


def _cmd_keygen(args: argparse.Namespace) -> int:
    """Generate a key pair and write it to disk."""
    out_dir = resolve_destination(args.out_dir)
    _warn_if_inside_git_worktree(out_dir)

    _warn_if_quantum_vulnerable(args, args.algorithm)
    passphrase = _new_key_passphrase(args)
    key = generate(
        args.algorithm,
        key_size=args.key_size,
        curve=args.curve,
        level=args.level,
    )
    result = write_key_pair(
        key,
        out_dir,
        name=args.name,
        fmt=args.format,
        passphrase=passphrase,
        overwrite=args.force,
    )

    warning = (
        f"{result.private_key_path} is a PRIVATE KEY. Anyone who reads it can "
        "impersonate you and decrypt data sent to you. It is stored with "
        "owner-only permissions; keep it that way, and never commit it or "
        "paste it into a chat or ticket."
    )

    # ML-KEM and ML-DSA sizes are parameter sets, not bit lengths. Calling
    # ML-KEM-768 "768 bits" would be simply wrong.
    if not result.key_size:
        size_label, size = "Key size", "n/a"
    elif result.algorithm in POST_QUANTUM:
        size_label, size = "Parameter set", str(result.key_size)
    else:
        size_label, size = "Key size", f"{result.key_size} bits"

    human = (
        f"{result.algorithm.upper()} key pair generated successfully.\n"
        f"Algorithm:   {result.algorithm}\n"
        f"{size_label + ':':<13} {size}\n"
        f"Private key: {result.private_key_path}\n"
        f"Public key:  {result.public_key_path}\n"
        f"Fingerprint: {result.fingerprint}\n"
        f"Encrypted:   {'yes' if result.private_key_encrypted else 'no'}"
    )

    # Custody warnings go to stderr, so they survive stdout being redirected
    # to a file or parsed as JSON, while --quiet still silences them for
    # automation that has already made an informed choice.
    if not args.quiet:
        print(warning, file=sys.stderr)
        if not result.private_key_encrypted:
            print(
                "\nWARNING: the private key is stored UNENCRYPTED because "
                "--no-passphrase was given.\n"
                "         Anything that can read the file has the key. "
                "Protect it with\n"
                "         filesystem permissions, and do not copy it.",
                file=sys.stderr,
            )
    _emit(
        args,
        human,
        {
            "private_key": str(result.private_key_path),
            "public_key": str(result.public_key_path),
            "fingerprint": result.fingerprint,
            "algorithm": result.algorithm,
            "key_size": result.key_size,
            "parameter_set": (
                result.key_size if result.algorithm in POST_QUANTUM else None
            ),
            "post_quantum": result.algorithm in POST_QUANTUM,
            "encrypted": result.private_key_encrypted,
            "replaced": result.replaced,
        },
    )
    if args.show_public:
        sys.stdout.buffer.write(encode_public_key(key.public_key(), fmt=args.format))
    return EXIT_OK


def _cmd_encrypt(args: argparse.Namespace) -> int:
    """Encrypt data to a public key, streaming so memory stays bounded."""
    public_key = load_public_key_file(args.public_key)
    with (
        _input_stream(args.input) as source,
        _output_stream(args.output, mode=PUBLIC_FILE_MODE, force=args.force) as (
            destination,
            reported,
        ),
    ):
        reporter, _ = _make_progress(args, args.input)
        written = encrypt_stream(
            public_key,
            source,
            destination,
            segment_size=args.segment_size,
            progress=reporter,
        )
        if reporter is not None:
            reporter.finish(written)
    where = reported[0] if reported else args.output
    _emit(
        args,
        f"Encrypted {written} bytes to {where}",
        {"output": where, "bytes": written, "streaming": True},
    )
    return EXIT_OK


def _cmd_decrypt(args: argparse.Namespace) -> int:
    """Decrypt a container, dispatching on its AEAD identifier.

    A streaming container is processed segment by segment; a one-shot
    container is read whole. The header says which, so the caller does not
    have to know.
    """
    private_key = _load_private_key(args, args.private_key)

    if _is_streaming_container(args.input):
        with (
            _input_stream(args.input) as source,
            _output_stream(args.output, mode=SECRET_FILE_MODE, force=args.force) as (
                destination,
                reported,
            ),
        ):
            reporter, _ = _make_progress(args, args.input)
            written = decrypt_stream(
                private_key, source, destination, progress=reporter
            )
            if reporter is not None:
                reporter.finish(written)
        where = reported[0] if reported else args.output
        _emit(
            args,
            f"Decrypted {written} bytes to {where}",
            {"output": where, "bytes": written, "streaming": True},
        )
        return EXIT_OK

    # One-shot, or stdin where the header cannot be peeked without consuming
    # it. Buffer, then dispatch on what we actually have.
    blob = _read_input(args.input, max_size=args.max_size)
    streaming = (
        len(blob) >= _PEEK_SIZE and blob[_AEAD_ID_OFFSET] == AEAD_AES_256_GCM_STREAM
    )
    if streaming:
        with _output_stream(args.output, mode=SECRET_FILE_MODE, force=args.force) as (
            destination,
            reported,
        ):
            written = decrypt_stream(private_key, io.BytesIO(blob), destination)
        where = reported[0] if reported else args.output
    else:
        plaintext = decrypt(private_key, blob)
        written = len(plaintext)
        where = _write_output(
            args.output, plaintext, mode=SECRET_FILE_MODE, force=args.force
        )
    _emit(
        args,
        f"Decrypted {written} bytes to {where}",
        {"output": where, "bytes": written, "streaming": streaming},
    )
    return EXIT_OK


def _cmd_sign(args: argparse.Namespace) -> int:
    """Sign data with a private key."""
    private_key = _load_private_key(args, args.private_key)
    signature = sign(private_key, _read_input(args.input, max_size=args.max_size))
    where = _write_output(
        args.output, signature, mode=PUBLIC_FILE_MODE, force=args.force
    )
    _emit(
        args,
        f"Wrote {len(signature)}-byte signature to {where}",
        {"output": where, "bytes": len(signature)},
    )
    return EXIT_OK


def _cmd_verify(args: argparse.Namespace) -> int:
    """Verify a signature over data."""
    public_key = load_public_key_file(args.public_key)
    verify(
        public_key,
        read_bytes(args.signature),
        _read_input(args.input, max_size=args.max_size),
    )
    _emit(args, "Signature is valid.", {"valid": True})
    return EXIT_OK


def _cmd_fingerprint(args: argparse.Namespace) -> int:
    """Print the SHA-256 fingerprint of a public key."""
    fingerprint = fingerprint_sha256(load_public_key_file(args.key))
    _emit(args, fingerprint, {"fingerprint": fingerprint})
    return EXIT_OK


def _cmd_convert(args: argparse.Namespace) -> int:
    """Convert a key between PEM, DER and OpenSSH encodings."""
    if args.private:
        key = _load_private_key(args, args.input)
        data = encode_private_key(key, fmt=args.to, passphrase=None)
        mode = SECRET_FILE_MODE
    else:
        data = encode_public_key(load_public_key_file(args.input), fmt=args.to)
        mode = PUBLIC_FILE_MODE

    where = _write_output(args.output, data, mode=mode, force=args.force)
    _emit(args, f"Wrote {args.to} key to {where}", {"output": where, "format": args.to})
    return EXIT_OK
