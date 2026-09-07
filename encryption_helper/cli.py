"""Command-line interface for :mod:`encryption_helper`.

This module owns everything to do with presentation: argument parsing, logging
configuration, human- and machine-readable output, and process exit codes. The
library modules underneath it do none of those things.

Exit codes:

===  ============================================================
0    Success.
1    An error occurred.
2    Usage error -- bad or missing arguments.
3    A destination file already exists and ``--force`` was not given.
4    Decryption or signature verification failed.
===  ============================================================

Passphrases are never accepted as a command-line value. Process arguments are
visible to every user on the system through ``/proc`` and are recorded in shell
history, so ``--passphrase-env`` and ``--passphrase-file`` are the only ways to
supply one.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from collections.abc import Sequence
from typing import Any, Final, NoReturn

from . import __version__
from ._io import (
    PUBLIC_FILE_MODE,
    SECRET_FILE_MODE,
    read_bytes,
    secure_write_bytes,
)
from .crypto import decrypt, encrypt, sign, verify
from .errors import (
    DecryptionError,
    EncryptionHelperError,
    KeyExistsError,
    SignatureVerificationError,
)
from .keys import (
    DEFAULT_RSA_KEY_SIZE,
    SUPPORTED_ALGORITHMS,
    SUPPORTED_CURVES,
    encode_private_key,
    encode_public_key,
    fingerprint_sha256,
    generate,
    load_private_key_file,
    load_public_key_file,
    write_key_pair,
)

__all__ = ["main"]

EXIT_OK: Final = 0
EXIT_ERROR: Final = 1
EXIT_USAGE: Final = 2
EXIT_KEY_EXISTS: Final = 3
EXIT_CRYPTO_FAILURE: Final = 4

_STDIO = "-"
_LOG_LEVELS: Final = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _configure_logging(args: argparse.Namespace) -> None:
    """Set up logging for the process from the parsed global flags."""
    if args.quiet:
        level = logging.ERROR
    elif args.log_level:
        level = getattr(logging, args.log_level)
    elif args.verbose >= 2:  # noqa: PLR2004 - -vv means debug
        level = logging.DEBUG
    elif args.verbose == 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )


def _emit(args: argparse.Namespace, human: str, payload: dict[str, Any]) -> None:
    """Write a result as either human text or JSON.

    JSON goes to stdout so it can be piped; human diagnostics that are not the
    result itself go to stderr elsewhere.
    """
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif not args.quiet:
        print(human)


def _resolve_passphrase(args: argparse.Namespace) -> bytes | None:
    """Read the passphrase from the environment or a file.

    Returns:
        The passphrase bytes, or :data:`None` if none was requested.

    Raises:
        SystemExit: If the named source is missing or empty.
    """
    if getattr(args, "passphrase_env", None):
        value = os.environ.get(args.passphrase_env)
        if not value:
            _fail_usage(
                f"Environment variable {args.passphrase_env} is unset or empty."
            )
        return value.encode()

    if getattr(args, "passphrase_file", None):
        data = read_bytes(args.passphrase_file).strip()
        if not data:
            _fail_usage(f"Passphrase file {args.passphrase_file} is empty.")
        return data

    return None


def _fail_usage(message: str) -> NoReturn:
    """Print a usage error to stderr and exit with :data:`EXIT_USAGE`."""
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(EXIT_USAGE)


def _read_input(source: str) -> bytes:
    """Read from a path, or from stdin when ``source`` is ``-``."""
    if source == _STDIO:
        return sys.stdin.buffer.read()
    return read_bytes(source)


def _write_output(destination: str, data: bytes, *, mode: int, force: bool) -> str:
    """Write to a path, or to stdout when ``destination`` is ``-``.

    Returns:
        A human-readable description of where the data went.
    """
    if destination == _STDIO:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return "<stdout>"
    path = secure_write_bytes(destination, data, mode=mode, overwrite=force)
    return str(path)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _cmd_keygen(args: argparse.Namespace) -> int:
    """Generate a key pair and write it to disk."""
    passphrase = _resolve_passphrase(args)
    key = generate(args.algorithm, key_size=args.key_size, curve=args.curve)
    paths = write_key_pair(
        key,
        args.out_dir,
        name=args.name,
        fmt=args.format,
        passphrase=passphrase,
        overwrite=args.force,
    )
    fingerprint = fingerprint_sha256(key.public_key())

    warning = (
        f"{paths.private_key} is a PRIVATE KEY. Anyone who reads it can "
        "impersonate you and decrypt data sent to you. It is stored with "
        "owner-only permissions; keep it that way, and never commit it or "
        "paste it into a chat or ticket."
    )
    if not passphrase:
        warning += (
            "\nIt is NOT encrypted. Consider --passphrase-env or "
            "--passphrase-file to protect it at rest."
        )

    human = (
        f"Private key: {paths.private_key}\n"
        f"Public key:  {paths.public_key}\n"
        f"Fingerprint: {fingerprint}\n\n{warning}"
    )
    _emit(
        args,
        human,
        {
            "private_key": str(paths.private_key),
            "public_key": str(paths.public_key),
            "fingerprint": fingerprint,
            "algorithm": args.algorithm,
            "encrypted": passphrase is not None,
        },
    )
    if args.show_public:
        sys.stdout.buffer.write(encode_public_key(key.public_key(), fmt=args.format))
    return EXIT_OK


def _cmd_encrypt(args: argparse.Namespace) -> int:
    """Encrypt data to a public key."""
    public_key = load_public_key_file(args.public_key)
    blob = encrypt(public_key, _read_input(args.input))
    where = _write_output(args.output, blob, mode=PUBLIC_FILE_MODE, force=args.force)
    _emit(
        args,
        f"Encrypted {len(blob)} bytes to {where}",
        {"output": where, "bytes": len(blob)},
    )
    return EXIT_OK


def _cmd_decrypt(args: argparse.Namespace) -> int:
    """Decrypt a container with a private key."""
    private_key = load_private_key_file(
        args.private_key, passphrase=_resolve_passphrase(args)
    )
    plaintext = decrypt(private_key, _read_input(args.input))
    where = _write_output(
        args.output, plaintext, mode=SECRET_FILE_MODE, force=args.force
    )
    _emit(
        args,
        f"Decrypted {len(plaintext)} bytes to {where}",
        {"output": where, "bytes": len(plaintext)},
    )
    return EXIT_OK


def _cmd_sign(args: argparse.Namespace) -> int:
    """Sign data with a private key."""
    private_key = load_private_key_file(
        args.private_key, passphrase=_resolve_passphrase(args)
    )
    signature = sign(private_key, _read_input(args.input))
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
    verify(public_key, read_bytes(args.signature), _read_input(args.input))
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
        key = load_private_key_file(args.input, passphrase=_resolve_passphrase(args))
        data = encode_private_key(key, fmt=args.to, passphrase=None)
        mode = SECRET_FILE_MODE
    else:
        data = encode_public_key(load_public_key_file(args.input), fmt=args.to)
        mode = PUBLIC_FILE_MODE

    where = _write_output(args.output, data, mode=mode, force=args.force)
    _emit(args, f"Wrote {args.to} key to {where}", {"output": where, "format": args.to})
    return EXIT_OK


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _add_passphrase_flags(parser: argparse.ArgumentParser) -> None:
    """Add the mutually exclusive passphrase source flags."""
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
            "Read the passphrase from this file. Trailing whitespace is "
            "stripped. Keep the file mode 0600."
        ),
    )


def _add_io_flags(parser: argparse.ArgumentParser, *, output: bool = True) -> None:
    """Add the shared ``--in``/``--out`` flags."""
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
        "--version", action="version", version=f"%(prog)s {__version__}"
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

    keygen = sub.add_parser(
        "keygen",
        help="Generate a key pair.",
        description="Generate a key pair and write it to disk.",
    )
    keygen.add_argument(
        "--algorithm",
        choices=SUPPORTED_ALGORITHMS,
        default="rsa",
        help="Key algorithm (default: rsa).",
    )
    keygen.add_argument(
        "--key-size",
        type=int,
        default=DEFAULT_RSA_KEY_SIZE,
        metavar="BITS",
        help=(
            f"RSA modulus size in bits (default: {DEFAULT_RSA_KEY_SIZE}). "
            "Ignored for non-RSA algorithms. Minimum 2048."
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
    _add_passphrase_flags(keygen)
    keygen.set_defaults(func=_cmd_keygen)

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

    dec = sub.add_parser(
        "decrypt",
        help="Decrypt data with a private key.",
        description="Decrypt a container produced by `encryption-helper encrypt`.",
    )
    dec.add_argument("--private-key", required=True, metavar="PATH")
    _add_io_flags(dec)
    _add_passphrase_flags(dec)
    dec.set_defaults(func=_cmd_decrypt)

    sgn = sub.add_parser(
        "sign",
        help="Sign data with a private key.",
        description="Sign data. RSA uses PSS with SHA-256.",
    )
    sgn.add_argument("--private-key", required=True, metavar="PATH")
    _add_io_flags(sgn)
    _add_passphrase_flags(sgn)
    sgn.set_defaults(func=_cmd_sign)

    vfy = sub.add_parser(
        "verify",
        help="Verify a signature.",
        description="Verify a signature over data. Exits 4 if it does not verify.",
    )
    vfy.add_argument("--public-key", required=True, metavar="PATH")
    vfy.add_argument("--signature", required=True, metavar="PATH")
    _add_io_flags(vfy, output=False)
    vfy.set_defaults(func=_cmd_verify)

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

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    """Run the command-line interface.

    Args:
        argv: Argument list, defaulting to :data:`sys.argv` when omitted.

    Returns:
        A process exit code. See the module docstring for their meanings.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args)

    try:
        result: int = args.func(args)
    except KeyExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_KEY_EXISTS
    except (DecryptionError, SignatureVerificationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CRYPTO_FAILURE
    except EncryptionHelperError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except BrokenPipeError:  # pragma: no cover - depends on the consumer
        # A downstream `head` closing the pipe is not an error.
        os._exit(EXIT_OK)
    except KeyboardInterrupt:  # pragma: no cover - interactive only
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR
    return result


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
