# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Find out which keys on disk need migrating, and why.

NIST IR 8547 (initial public draft) deprecates the classical public-key
algorithms from 2030 and disallows them from 2035. Acting on that begins with
scoping: which of the keys, certificates and encrypted files already on disk
are affected.

This example builds a directory resembling a real one, scans it, and shows
how to read the result -- including the two cases that are easy to get wrong.

Run:
    python examples/07_inventory_and_migration.py
"""

from __future__ import annotations

from pathlib import Path

from _workspace import workspace
from encryption_helper import (
    assess,
    encode_private_key,
    encode_public_key,
    encrypt,
    generate,
    horizon,
    scan,
    summarise,
)


def build_tree(root: Path) -> None:
    """Populate a directory with a realistic mix of material."""
    legacy = generate("rsa", key_size=2048)
    (root / "service.pub").write_bytes(encode_public_key(legacy.public_key()))
    (root / "service.pem").write_bytes(encode_private_key(legacy, passphrase=None))
    # A key with a passphrase: present, but its algorithm is not readable.
    (root / "vault.pem").write_bytes(
        encode_private_key(legacy, passphrase=b"a-long-passphrase")
    )
    (root / "archive.enc").write_bytes(encrypt(legacy.public_key(), b"records"))
    modern = generate("mlkem")
    (root / "payments.pub").write_bytes(encode_public_key(modern.public_key()))
    (root / "notes.txt").write_text("not cryptographic material")


def main() -> int:
    """Scan a directory and explain what the findings mean."""
    root = workspace()
    build_tree(root)

    findings = scan([root])
    summary = summarise(findings)

    print(f"{'file':<16} {'kind':<22} {'algorithm':<12} action")
    print("-" * 70)
    for finding in findings:
        algorithm = finding.algorithm or "undetermined"
        if finding.replacements:
            action = "migrate to " + " or ".join(finding.replacements)
        elif finding.undetermined:
            action = "review manually"
        else:
            action = "none"
        print(f"{finding.path.name:<16} {finding.kind:<22} {algorithm:<12} {action}")

    print()
    print(f"examined          {summary['examined']}")
    print(f"needing migration {summary['action_required']}")
    print(f"needing review    {summary['undetermined']}")
    print(f"needing attention {summary['needs_attention']}")
    print()

    # --- The first easy mistake -------------------------------------------
    print("notes.txt is absent from the report: classification is by file")
    print("contents, not by extension, so an ordinary file is not a finding")
    print("and a key with no extension still is.")
    print()

    # --- The second easy mistake ------------------------------------------
    print("vault.pem reports as undetermined, not as safe. Its algorithm is")
    print("inside the encrypted structure and the scan does not ask for a")
    print("passphrase, so `action_required` is false for that one reason.")
    print("Gate a pipeline on `needs_attention`, or a well-protected")
    print("RSA-2048 key passes because it was well protected.")
    print()

    # --- The third easy mistake -------------------------------------------
    rsa_posture = assess("rsa", key_size=2048)
    print(
        f"RSA alone -> replacements {rsa_posture.replacements}, "
        f"replacement {rsa_posture.replacement}"
    )
    print("RSA can encrypt and sign, and no single post-quantum algorithm")
    print("replaces both, so there is no one answer until the purpose is")
    print("known:")
    for purpose in ("encrypt", "sign"):
        resolved = assess("rsa", key_size=2048, purpose=purpose)
        print(f"  used to {purpose:<8} -> {resolved.replacement}")
    print()

    dates = horizon()
    print(
        f"deprecated from {dates['deprecated_from']}, "
        f"disallowed from {dates['disallowed_from']}"
    )
    print()
    print("Note:", dates["validation_note"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
