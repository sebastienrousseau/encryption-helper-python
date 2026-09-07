# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
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
import getpass
import json
import logging
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, Final, NoReturn

from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes

from . import __version__
from ._io import (
    PUBLIC_FILE_MODE,
    SECRET_FILE_MODE,
    read_bytes,
    resolve_destination,
    secure_write_bytes,
)
from .crypto import decrypt, encrypt, sign, verify
from .errors import (
    DecryptionError,
    EncryptionHelperError,
    KeyExistsError,
    KeyReadError,
    SignatureVerificationError,
)
from .keys import (
    ALLOWED_RSA_KEY_SIZES,
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

#: Upper bound on a passphrase file. Vastly larger than any real passphrase,
#: small enough that pointing --passphrase-file at a disk image is an error
#: rather than an out-of-memory event.
MAX_PASSPHRASE_FILE_BYTES: Final = 64 * 1024

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


def _passphrase_from_source(args: argparse.Namespace) -> bytes | None:
    r"""Read a passphrase from an environment variable or a file.

    Neither source is echoed back on failure. An error says *which* source was
    unusable and why, never what it contained.

    **Environment variable.** Taken verbatim, apart from a whitespace-only
    value being rejected: that is almost always an unset-variable accident,
    and it offers no protection. A value with meaningful leading or trailing
    spaces is preserved.

    **File.** Exactly one trailing newline is removed -- ``LF`` or ``CRLF`` --
    because a text editor appends one and a user who types ``secret`` into a
    file means ``secret``. Nothing else is stripped, so a passphrase may
    legitimately begin or end with a space, contain internal newlines, or not
    be valid UTF-8.

    Returns:
        The passphrase, or :data:`None` if neither source was requested.

    Raises:
        SystemExit: If the named source is missing, empty, or unusable.
    """
    if getattr(args, "passphrase_env", None):
        value = os.environ.get(args.passphrase_env)
        if value is None:
            _fail_usage(f"Environment variable {args.passphrase_env} is not set.")
        if not value.strip():
            _fail_usage(
                f"Environment variable {args.passphrase_env} is empty or "
                "contains only whitespace, which would not protect the key."
            )
        return _as_passphrase_bytes(value)

    if getattr(args, "passphrase_file", None):
        path = Path(args.passphrase_file).expanduser()
        _reject_oversized_passphrase_file(path)
        _warn_if_passphrase_file_is_readable(path)
        data = _strip_one_trailing_newline(read_bytes(path))
        if not data.strip():
            _fail_usage(
                f"Passphrase file {args.passphrase_file} is empty or contains "
                "only whitespace, which would not protect the key."
            )
        return _as_passphrase_bytes(data)

    return None


def _as_passphrase_bytes(value: str | bytes) -> bytes:
    r"""Convert a passphrase to bytes. The one place this transition happens.

    All three sources converge here so no source can acquire its own encoding
    behaviour by accident:

    * the interactive prompt and ``--passphrase-env`` yield :class:`str`, which
      is UTF-8 encoded;
    * ``--passphrase-file`` yields :class:`bytes`, which pass through
      unchanged, so a file may hold a byte-exact secret that is not valid
      UTF-8 -- a random-bytes secret from ``head -c 32 /dev/urandom``, say.

    Args:
        value: Passphrase text or raw bytes.

    Returns:
        The passphrase as bytes, ready for ``BestAvailableEncryption``.

    Example:
        >>> _as_passphrase_bytes("secret")
        b'secret'
        >>> _as_passphrase_bytes(b"\xff\xfe raw")
        b'\xff\xfe raw'
    """
    return value if isinstance(value, bytes) else value.encode("utf-8")


def _reject_oversized_passphrase_file(path: Path) -> None:
    """Refuse a passphrase file larger than :data:`MAX_PASSPHRASE_FILE_BYTES`.

    The size is checked before reading, so an enormous file is never loaded
    into memory. This is robustness rather than a security control: pointing
    ``--passphrase-file`` at a log or a disk image is a mistake, and it should
    fail as one.

    Raises:
        SystemExit: If the file is too large.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return  # read_bytes() will report the real problem in a moment.
    if size > MAX_PASSPHRASE_FILE_BYTES:
        _fail_usage(
            f"Passphrase file {path} is {size} bytes, which exceeds the "
            f"{MAX_PASSPHRASE_FILE_BYTES}-byte limit. A passphrase file is "
            "expected to contain a passphrase."
        )


def _warn_if_passphrase_file_is_readable(path: Path) -> None:
    """Warn if a passphrase file is group- or world-readable on POSIX.

    Deliberately a warning, not a refusal. CI secret mounts, container
    tmpfs and enterprise filesystems have permission models this check cannot
    reason about, so rejecting would break legitimate setups while promising a
    guarantee we cannot make.

    On Windows this is skipped entirely rather than pretending Unix mode bits
    describe an ACL.
    """
    if sys.platform == "win32":
        return
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:  # pragma: no cover - reported by the subsequent read
        return
    if mode & 0o077:
        print(
            f"warning: passphrase file {path} is mode {mode:04o}, readable by "
            "others.\n"
            "         Consider `chmod 600` unless your platform's access "
            "control makes that\n"
            "         unnecessary.",
            file=sys.stderr,
        )


def _strip_one_trailing_newline(data: bytes) -> bytes:
    r"""Remove a single trailing ``LF`` or ``CRLF``, and nothing else.

    Args:
        data: Raw file contents.

    Returns:
        The contents without one trailing line ending.

    Example:
        >>> _strip_one_trailing_newline(b"secret\n")
        b'secret'
        >>> _strip_one_trailing_newline(b"secret\r\n")
        b'secret'
        >>> _strip_one_trailing_newline(b"secret\n\n")
        b'secret\n'
        >>> _strip_one_trailing_newline(b" secret ")
        b' secret '
    """
    if data.endswith(b"\r\n"):
        return data[:-2]
    if data.endswith(b"\n"):
        return data[:-1]
    return data


def _interactive() -> bool:
    """Whether a human is present to answer a prompt."""
    return sys.stdin.isatty() and sys.stderr.isatty()


def _prompt_new_passphrase() -> bytes:
    """Prompt twice for a new passphrase, without echoing it.

    Returns:
        The confirmed passphrase.

    Raises:
        SystemExit: If the two entries differ or the passphrase is empty.
    """
    first = getpass.getpass("Passphrase for the new private key: ")
    if not first.strip():
        _fail_usage(
            "An empty passphrase does not protect the key. Pass "
            "--no-passphrase if you intend to store it unencrypted."
        )
    if getpass.getpass("Confirm passphrase: ") != first:
        _fail_usage("The passphrases did not match.")
    return _as_passphrase_bytes(first)


def _new_key_passphrase(args: argparse.Namespace) -> bytes | None:
    """Decide how a newly generated private key will be protected.

    Storing a private key in plaintext is a real decision, so it has to be a
    deliberate one. A passphrase comes from an explicit source or an
    interactive prompt; going without requires ``--no-passphrase``. There is
    no path that silently produces an unprotected key.

    Returns:
        The passphrase, or :data:`None` if the user opted out explicitly.

    Raises:
        SystemExit: If no source was given and none can be established.
    """
    if args.no_passphrase:
        return None

    supplied = _passphrase_from_source(args)
    if supplied is not None:
        return supplied

    if _interactive():
        return _prompt_new_passphrase()

    print(
        "error: refusing to write an unencrypted private key by default.\n"
        "  Supply a passphrase with --passphrase-env VAR or "
        "--passphrase-file PATH,\n"
        "  or pass --no-passphrase to store the key unencrypted on purpose.",
        file=sys.stderr,
    )
    raise SystemExit(EXIT_USAGE)


def _existing_key_passphrase(args: argparse.Namespace) -> bytes | None:
    """Read the passphrase for an existing key, if one was supplied."""
    return _passphrase_from_source(args)


def _load_private_key(args: argparse.Namespace, path: str) -> PrivateKeyTypes:
    """Load a private key, prompting for a passphrase only if one is needed.

    Tries without a passphrase first, so an unencrypted key never triggers a
    pointless prompt, and prompts once if that fails and a human is present.

    Raises:
        KeyReadError: If the key cannot be loaded.
    """
    supplied = _existing_key_passphrase(args)
    if supplied is not None:
        return load_private_key_file(path, passphrase=supplied)

    try:
        return load_private_key_file(path)
    except KeyReadError:
        if not _interactive():
            raise
    prompt = getpass.getpass(f"Passphrase for {path}: ")
    return load_private_key_file(path, passphrase=_as_passphrase_bytes(prompt))


def _warn_if_inside_git_worktree(directory: Path) -> None:
    """Warn when key material is about to be written inside a git checkout.

    ``.gitignore`` is not a security boundary -- it can be bypassed with
    ``git add -f`` -- so the useful defence is to tell the user before the key
    exists, not after it is committed.
    """
    for candidate in [directory, *directory.parents]:
        if (candidate / ".git").exists():
            print(
                f"warning: {directory} is inside the git repository at "
                f"{candidate}.\n"
                "         Private keys should not live in a working tree. "
                "Use --out-dir to\n"
                "         write them somewhere outside it.",
                file=sys.stderr,
            )
            return


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
    out_dir = resolve_destination(args.out_dir)
    _warn_if_inside_git_worktree(out_dir)

    passphrase = _new_key_passphrase(args)
    key = generate(args.algorithm, key_size=args.key_size, curve=args.curve)
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

    size = f"{result.key_size} bits" if result.key_size else "n/a"
    human = (
        f"{result.algorithm.upper()} key pair generated successfully.\n"
        f"Algorithm:   {result.algorithm}\n"
        f"Key size:    {size}\n"
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
            "encrypted": result.private_key_encrypted,
            "replaced": result.replaced,
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
    private_key = _load_private_key(args, args.private_key)
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
    private_key = _load_private_key(args, args.private_key)
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
        key = _load_private_key(args, args.input)
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
    except Exception:
        # An unexpected exception's text may quote a path, an argument, or a
        # value the user never meant to surface. Print a fixed message and
        # send the detail to the log, which the operator controls.
        logger.exception("Unexpected internal error")
        print(
            "error: unexpected internal error. Re-run with --log-level DEBUG "
            "for details, and please report this.",
            file=sys.stderr,
        )
        return EXIT_ERROR
    return result


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
