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

#: Bytes of a container needed before its AEAD identifier can be read:
#: 4 magic, 1 version, 1 kem_id, then the aead_id byte.
_AEAD_ID_OFFSET: Final = 6
_PEEK_SIZE: Final = _AEAD_ID_OFFSET + 1

#: Binary unit step, for formatting byte counts.
_UNIT_STEP: Final = 1024
