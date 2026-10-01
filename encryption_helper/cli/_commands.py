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
from ..crypto.metadata import HEADER_SIZE, describe_container
from ..crypto.streaming import decrypt_stream, encrypt_stream
from ..inventory import Finding, scan, summarise
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
from ..policy import (
    NIST_DEPRECATED_FROM,
    NIST_DISALLOWED_FROM,
    horizon,
    purposes,
)
from ._constants import (
    _AEAD_ID_OFFSET,
    _PEEK_SIZE,
    EXIT_ERROR,
    EXIT_OK,
)
from ._output import _emit, runtime_version
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


def _capabilities() -> dict[str, Any]:
    """Describe what this build can do, and what is on a deadline.

    Machine-readable, so a cryptographic inventory process can identify
    quantum-vulnerable material without parsing help text. The horizon is
    reported per algorithm rather than left implicit, and the validation
    note is included so any report quoting the horizon also carries the
    caveat that applies to it.
    """
    return {
        "version": runtime_version(),
        "algorithms": {
            name: {
                "quantum_vulnerable": name in QUANTUM_VULNERABLE,
                "post_quantum": name in POST_QUANTUM,
                "deprecated_from": (
                    NIST_DEPRECATED_FROM if name in QUANTUM_VULNERABLE else None
                ),
                "disallowed_from": (
                    NIST_DISALLOWED_FROM if name in QUANTUM_VULNERABLE else None
                ),
                "can_encrypt": purposes(name)["encrypt"],
                "can_sign": purposes(name)["sign"],
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
        "horizon": horizon(),
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
        f"note: {algorithm} would be broken by a cryptanalytically relevant "
        "quantum computer,\n"
        "      which does not exist today. NIST IR 8547 (initial public "
        "draft) deprecates it\n"
        f"      from {NIST_DEPRECATED_FROM} and disallows it from "
        f"{NIST_DISALLOWED_FROM}. Data encrypted now can be recorded\n"
        "      and decrypted later, so where confidentiality must outlive "
        "those dates use\n"
        "      --algorithm mlkem (encryption) or mldsa (signing).",
        file=sys.stderr,
    )


def _capability_phrase(algorithm: str) -> str:
    """Describe what holding this private key would let someone do.

    The custody warning used to say a leaked key let an attacker "impersonate
    you and decrypt data sent to you". That is true only of RSA. For ML-KEM
    and X25519, which cannot sign, the impersonation half is wrong; for
    ML-DSA, Ed25519, Ed448 and ECDSA, which cannot decrypt, the other half is.
    A warning that is half wrong is one a reader learns to discount, so the
    phrase is derived from what the algorithm can actually do.
    """
    able = purposes(algorithm)
    clauses = []
    if able["encrypt"]:
        clauses.append("decrypt data encrypted to this key")
    if able["sign"]:
        clauses.append("produce signatures that verify against this key")
    if not clauses:  # pragma: no cover - every supported algorithm does one
        return "use this key"
    return " and ".join(clauses)


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
        f"{result.private_key_path} is a private key. Anyone able to read "
        f"this file can {_capability_phrase(result.algorithm)}. It is stored "
        "with owner-only permissions, which should be preserved. Do not "
        "commit it to version control, and do not transmit it through chat "
        "or ticketing systems."
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


def _cmd_inspect(args: argparse.Namespace) -> int:
    """Report a container's algorithms without decrypting it.

    Reads only the header. No private key is involved, so this answers an
    auditor's question -- which algorithm protects this file -- without
    anyone having to hold the key that protects it.
    """
    with _input_stream(args.input) as source:
        header = source.read(HEADER_SIZE)

    info = describe_container(header)
    posture_note = (
        "Vulnerable to a quantum computer. Data recorded now can be decrypted "
        "once a cryptanalytically relevant quantum computer exists, so this "
        "file should be re-encrypted if its confidentiality must outlast that "
        "point."
        if info.quantum_vulnerable
        else "Not vulnerable to a quantum computer."
    )
    rows = [
        f"Format version:     {info.format_version}"
        + ("" if info.readable else "  (too new for this build to read)"),
        f"Key establishment:  {info.key_establishment or 'unrecognised'}"
        + (
            f"  [{info.key_establishment_standard}]"
            if info.key_establishment_standard
            else ""
        ),
        f"Content encryption: {info.content_encryption or 'unrecognised'}",
        f"Segmented:          {'yes' if info.segmented else 'no'}",
        "",
        posture_note,
    ]
    _emit(args, "\n".join(rows), info.as_dict())
    return EXIT_OK


def _scan_rows(findings: list[Finding], summary: dict[str, Any]) -> list[str]:
    """Render findings as a fixed-width table for a terminal."""
    if not findings:
        return ["No recognised cryptographic material found."]
    rows = [
        f"{'file':<40} {'kind':<22} {'algorithm':<12} action",
        "-" * 86,
    ]
    for finding in findings:
        algorithm = finding.algorithm or "undetermined"
        if finding.key_size:
            algorithm = f"{algorithm}-{finding.key_size}"
        if finding.action_required:
            action = f"migrate to {' or '.join(finding.replacements)}"
        elif finding.undetermined:
            action = "review manually"
        else:
            action = "none"
        rows.append(
            f"{str(finding.path)[-40:]:<40} {finding.kind:<22} {algorithm:<12} {action}"
        )
    rows += [
        "",
        f"{summary['examined']} examined, "
        f"{summary['action_required']} needing migration, "
        f"{summary['undetermined']} needing manual review.",
        "",
        f"Algorithms with a deadline are deprecated from "
        f"{NIST_DEPRECATED_FROM} and disallowed from {NIST_DISALLOWED_FROM} "
        "by NIST IR 8547.",
    ]
    return rows


def _cmd_scan(args: argparse.Namespace) -> int:
    """Report cryptographic material on disk and its migration status.

    Reads public material only. Encrypted private keys are reported as
    needing manual review rather than unlocked: a scan is not a reason to
    handle a passphrase.
    """
    findings = scan(args.paths)
    summary = summarise(findings)
    payload: dict[str, Any] = {
        "summary": summary,
        "findings": [finding.as_dict() for finding in findings],
        "horizon": horizon(),
    }
    _emit(args, "\n".join(_scan_rows(findings, summary)), payload)

    if args.fail_on_finding and summary["needs_attention"]:
        return EXIT_ERROR
    return EXIT_OK
