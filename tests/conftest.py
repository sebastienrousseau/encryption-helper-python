# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Shared fixtures.

Fixtures here exist so that no test file needs to repeat key generation or
temporary-directory boilerplate. Note what is *not* here: there is no mock
logger fixture and no patched ``open``. Tests in this suite exercise the real
code against a real filesystem, because the previous suite's habit of mocking
the unit under test is exactly why a totally broken write path shipped with
"97% coverage".
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from encryption_helper.keys import generate_ecdsa, generate_ed25519, generate_rsa


@pytest.fixture(scope="session")
def rsa_key() -> rsa.RSAPrivateKey:
    """A 2048-bit RSA key, generated once for the whole session.

    2048 rather than the library default of 3072 purely so the suite stays
    fast; the size is not what any test is asserting on.
    """
    return generate_rsa(key_size=2048)


@pytest.fixture(scope="session")
def ed25519_key() -> ed25519.Ed25519PrivateKey:
    """An Ed25519 key, generated once for the whole session."""
    return generate_ed25519()


@pytest.fixture(scope="session")
def ecdsa_key() -> ec.EllipticCurvePrivateKey:
    """An ECDSA P-256 key, generated once for the whole session."""
    return generate_ecdsa(curve="p256")


@pytest.fixture(scope="session")
def ed448_key():
    """An Ed448 key, generated once for the whole session."""
    from encryption_helper.keys import generate_ed448

    return generate_ed448()


@pytest.fixture(scope="session")
def x25519_key():
    """An X25519 key for encryption, generated once for the whole session."""
    from encryption_helper.keys import generate_x25519

    return generate_x25519()


@pytest.fixture(scope="session")
def mlkem_key():
    """An ML-KEM-768 key, generated once for the whole session."""
    from encryption_helper.keys import generate_mlkem

    return generate_mlkem(level=768)


@pytest.fixture(scope="session")
def mldsa_key():
    """An ML-DSA-65 key, generated once for the whole session."""
    from encryption_helper.keys import generate_mldsa

    return generate_mldsa(level=65)


@pytest.fixture(scope="session")
def mlkem1024_key():
    """An ML-KEM-1024 key, generated once for the whole session."""
    from encryption_helper.keys import generate_mlkem

    return generate_mlkem(level=1024)
