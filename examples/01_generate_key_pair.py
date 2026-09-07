# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Generate a key pair and store it safely.

Shows the three-step separation the library is built around: generation
produces a key object, serialisation turns it into bytes, and storage applies
the permission and overwrite rules. Nothing prints or logs the private key.

Run:
    python examples/01_generate_key_pair.py
"""

from __future__ import annotations

import stat
import sys
import tempfile
from pathlib import Path

from encryption_helper import fingerprint_sha256, generate_rsa, write_key_pair


def main() -> int:
    """Generate a passphrase-protected RSA key pair into a temporary directory."""
    destination = Path(tempfile.mkdtemp(prefix="encryption-helper-example-"))

    # 1. Generate. No I/O, no logging, no printing.
    key = generate_rsa(key_size=2048)

    # 2. Serialise and store. A passphrase encrypts the key at rest; pass
    #    `passphrase=None` only when you genuinely want a plaintext key.
    result = write_key_pair(
        key,
        destination,
        name="service",
        passphrase=b"correct horse battery staple",
    )

    print(f"Algorithm:   {result.algorithm}")
    print(f"Key size:    {result.key_size} bits")
    print(f"Private key: {result.private_key_path}")
    print(f"Public key:  {result.public_key_path}")
    print(f"Fingerprint: {result.fingerprint}")
    print(f"Encrypted:   {result.private_key_encrypted}")

    # The result object carries no secret, so printing it is safe.
    assert b"PRIVATE KEY" not in repr(result).encode()

    if sys.platform != "win32":
        mode = stat.S_IMODE(result.private_key_path.stat().st_mode)
        print(f"Private key mode: {mode:04o}")
        assert mode == 0o600, "private key should be owner-only"

    # The fingerprint identifies the key without exposing it, and matches
    # `ssh-keygen -lf` for the same public key.
    assert fingerprint_sha256(key.public_key()) == result.fingerprint
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
