# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Load keys from disk and convert between encodings.

Loading auto-detects PEM, DER and OpenSSH, and failures surface as
`KeyReadError` rather than as whichever exception the backend happened to
raise.

Run:
    python examples/04_load_and_convert.py
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from encryption_helper import (
    KeyReadError,
    encode_public_key,
    generate_ed25519,
    load_private_key_file,
    load_public_key_file,
    write_key_pair,
)


def main() -> int:
    """Write a key pair, reload it, and re-encode the public half."""
    destination = Path(tempfile.mkdtemp(prefix="encryption-helper-example-"))
    key = generate_ed25519()
    result = write_key_pair(key, destination, name="id", passphrase=b"a passphrase")

    # A passphrase-protected key needs that passphrase to load.
    try:
        load_private_key_file(result.private_key_path)
    except KeyReadError as exc:
        print(f"without passphrase: {exc}")

    private = load_private_key_file(result.private_key_path, passphrase=b"a passphrase")
    public = load_public_key_file(result.public_key_path)
    assert private.public_key().public_bytes_raw() == public.public_bytes_raw()
    print("reloaded pair matches")

    # Re-encode the public key for other tools. The OpenSSH form is what
    # `authorized_keys` expects.
    for fmt in ("pem", "der", "openssh"):
        encoded = encode_public_key(public, fmt=fmt)
        preview = encoded[:32].decode("ascii", errors="replace").strip()
        print(f"{fmt:>8}: {len(encoded):>4} bytes  {preview}...")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
