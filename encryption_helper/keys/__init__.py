# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Key generation, serialisation, loading, storage and fingerprinting."""

from __future__ import annotations

from .fingerprint import fingerprint_sha256
from .generate import (
    ALLOWED_RSA_KEY_SIZES,
    DEFAULT_ALGORITHM,
    DEFAULT_MLDSA_LEVEL,
    DEFAULT_MLKEM_LEVEL,
    DEFAULT_RSA_KEY_SIZE,
    MIN_RSA_KEY_SIZE,
    POST_QUANTUM,
    QUANTUM_VULNERABLE,
    SUPPORTED_ALGORITHMS,
    SUPPORTED_CURVES,
    SUPPORTED_MLDSA_LEVELS,
    SUPPORTED_MLKEM_LEVELS,
    generate,
    generate_ecdsa,
    generate_ed448,
    generate_ed25519,
    generate_mldsa,
    generate_mlkem,
    generate_rsa,
    generate_x25519,
)
from .load import (
    load_private_key,
    load_private_key_file,
    load_public_key,
    load_public_key_file,
)
from .serialize import encode_private_key, encode_public_key
from .store import KeyGenerationResult, describe_key, write_key_pair

__all__ = [
    "ALLOWED_RSA_KEY_SIZES",
    "DEFAULT_ALGORITHM",
    "DEFAULT_MLDSA_LEVEL",
    "DEFAULT_MLKEM_LEVEL",
    "DEFAULT_RSA_KEY_SIZE",
    "MIN_RSA_KEY_SIZE",
    "POST_QUANTUM",
    "QUANTUM_VULNERABLE",
    "SUPPORTED_ALGORITHMS",
    "SUPPORTED_CURVES",
    "SUPPORTED_MLDSA_LEVELS",
    "SUPPORTED_MLKEM_LEVELS",
    "KeyGenerationResult",
    "describe_key",
    "encode_private_key",
    "encode_public_key",
    "fingerprint_sha256",
    "generate",
    "generate_ecdsa",
    "generate_ed448",
    "generate_ed25519",
    "generate_mldsa",
    "generate_mlkem",
    "generate_rsa",
    "generate_x25519",
    "load_private_key",
    "load_private_key_file",
    "load_public_key",
    "load_public_key_file",
    "write_key_pair",
]
