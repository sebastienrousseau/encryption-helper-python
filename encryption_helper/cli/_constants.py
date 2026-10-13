# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Values shared across the CLI layer.

These live apart from the modules that use them so the CLI submodules can
import them without importing each other.
"""

from __future__ import annotations

from typing import Final

EXIT_OK: Final = 0
EXIT_ERROR: Final = 1
EXIT_USAGE: Final = 2
EXIT_KEY_EXISTS: Final = 3
EXIT_CRYPTO_FAILURE: Final = 4
#: ``scan --fail-on-finding`` found material that needs attention. Distinct
#: from :data:`EXIT_ERROR` so a pipeline can tell "the tree has findings"
#: from "the scanner failed": the run itself succeeded, and its JSON result
#: is a normal ``status: ok`` document.
EXIT_FINDINGS: Final = 5
#: The reader of stdout went away before the output was complete -- the
#: ``head -c 10`` in ``decrypt big | head -c 10``. 128 + SIGPIPE (13), the
#: status a shell reports for a process killed by that signal, so ``set -o
#: pipefail`` sees the truncation. It used to exit 0, which reported a
#: partial plaintext as a complete one. Nothing is written to stderr: the
#: consumer closed the pipe on purpose, and the status says what happened.
EXIT_BROKEN_PIPE: Final = 141

#: Version of the ``--json`` output contract.
#:
#: Every JSON document this CLI emits carries this number. It is incremented
#: only when a change could break a consumer: a field removed, renamed, or
#: given a different meaning. Adding a field does not increment it, so a
#: consumer should ignore fields it does not recognise.
#:
#: The contract is specified in ``docs/schemas/cli-output-v1.json``.
JSON_SCHEMA_VERSION: Final = 1

#: Machine-readable code for each failure, keyed by exit code. Automation
#: should branch on these rather than on message text, which is not stable.
ERROR_CODES: Final = {
    1: "error",
    2: "usage",
    3: "key-exists",
    4: "crypto-failure",
}

_STDIO = "-"
_LOG_LEVELS: Final = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

#: Upper bound on a passphrase file. Vastly larger than any real passphrase,
#: small enough that pointing --passphrase-file at a disk image is an error
#: rather than an out-of-memory event.
MAX_PASSPHRASE_FILE_BYTES: Final = 64 * 1024

#: Default ceiling on data passed to encrypt or decrypt.
#:
#: Encryption holds the whole message in memory, and peak usage measures at
#: roughly four times the payload -- plaintext, ciphertext and intermediate
#: copies are all resident. A 1 GiB file therefore needs about 4 GiB. Rather
#: than let that become an out-of-memory kill, the CLI refuses and says so.
#: Raise it with --max-size if you have the headroom.
DEFAULT_MAX_INPUT_BYTES: Final = 64 * 1024 * 1024

#: Largest detached signature file read. The largest signature this package
#: produces, ML-DSA-87, is 4,627 bytes.
MAX_SIGNATURE_FILE_BYTES: Final = 1024 * 1024

#: Bytes of a container needed before its AEAD identifier can be read:
#: 4 magic, 1 version, 1 kem_id, then the aead_id byte.
_AEAD_ID_OFFSET: Final = 6
_PEEK_SIZE: Final = _AEAD_ID_OFFSET + 1

#: Binary unit step, for formatting byte counts.
_UNIT_STEP: Final = 1024
