# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""One table of key types, and every generated key is in it.

The class -> (algorithm, size, label) mapping was copied into ``_labels``,
``keys/store.py`` and ``inventory.py``, and the copies drifted: ``store``
lost X448, so ``describe_key`` reported an X448 key as ``x448privatekey``
with no size. These tests pin the single table and its coverage.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa, x448
from encryption_helper import inventory
from encryption_helper._labels import KEY_TYPES, key_label, key_type
from encryption_helper.keys.generate import (
    SUPPORTED_ALGORITHMS,
    SUPPORTED_CURVES,
    SUPPORTED_MLDSA_LEVELS,
    SUPPORTED_MLKEM_LEVELS,
    generate,
)
from encryption_helper.keys.store import describe_key


def _every_generatable_key():
    """One key per algorithm and parameter set :func:`generate` offers."""
    for algorithm in SUPPORTED_ALGORITHMS:
        if algorithm == "rsa":
            yield pytest.param("rsa", {"key_size": 2048}, id="rsa")
        elif algorithm == "ecdsa":
            for curve in SUPPORTED_CURVES:
                yield pytest.param("ecdsa", {"curve": curve}, id=f"ecdsa-{curve}")
        elif algorithm == "mlkem":
            for level in SUPPORTED_MLKEM_LEVELS:
                yield pytest.param("mlkem", {"level": level}, id=f"mlkem-{level}")
        elif algorithm == "mldsa":
            for level in SUPPORTED_MLDSA_LEVELS:
                yield pytest.param("mldsa", {"level": level}, id=f"mldsa-{level}")
        else:
            yield pytest.param(algorithm, {}, id=algorithm)


@pytest.mark.parametrize(("algorithm", "options"), list(_every_generatable_key()))
def test_every_generatable_key_is_described_and_labelled(algorithm, options):
    key = generate(algorithm, **options)
    name, size = describe_key(key)
    assert name == algorithm
    assert size is not None
    assert "unsupported" not in key_label(key)
    assert key_label(key) == key_label(key.public_key())
    if isinstance(key, rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey):
        assert key_type(key) is None, "sized-on-the-instance types stay out"
    else:
        entry = key_type(key)
        assert entry is not None, f"{type(key).__name__} is missing from KEY_TYPES"
        assert key_type(key.public_key()) is entry
        assert (entry.algorithm, entry.size) == (name, size)


@pytest.mark.parametrize("entry", KEY_TYPES, ids=lambda e: e.label)
def test_each_entry_pairs_the_right_classes(entry):
    private = entry.private.generate()
    assert isinstance(private.public_key(), entry.public)
    assert key_type(private) is entry
    assert key_label(private) == entry.label


def test_entries_are_unique():
    assert len({e.private for e in KEY_TYPES}) == len(KEY_TYPES)
    assert len({e.public for e in KEY_TYPES}) == len(KEY_TYPES)
    assert len({(e.algorithm, e.size) for e in KEY_TYPES}) == len(KEY_TYPES)


def test_x448_is_described_like_its_siblings():
    """The drifted case: store's copy of the table had no X448 row."""
    assert describe_key(x448.X448PrivateKey.generate()) == ("x448", 448)


def test_a_key_outside_the_table_keeps_the_fallback_description():
    key = dsa.generate_private_key(2048)
    assert key_type(key) is None
    assert describe_key(key) == (type(key).__name__.lower(), None)
    assert key_label(key) == "a DSA key"


def test_the_inventory_names_keys_from_the_same_table():
    """The scan reads KEY_TYPES; it no longer keeps a copy that can drift."""
    assert tuple(inventory._PUBLIC_KEY_NAMES) == tuple(
        (e.public, e.algorithm, e.size) for e in KEY_TYPES
    )
