# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Benchmarks for the operations whose cost users actually feel.

Deliberately dependency-free: `time.perf_counter` and the standard library,
so this runs anywhere the package does and needs no pytest plugin.

Run:
    python benches/bench_crypto.py              # default set
    python benches/bench_crypto.py --quick      # fewer iterations
    python benches/bench_crypto.py --json       # machine-readable

These are *indicative*, not a regression gate. Key generation in particular
has enormous variance -- RSA generation is a search for primes -- so treat a
single run as a rough shape, not a measurement.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from encryption_helper import (
    decrypt,
    encode_private_key,
    encrypt,
    fingerprint_sha256,
    generate_ecdsa,
    generate_ed25519,
    generate_mldsa,
    generate_mlkem,
    generate_rsa,
    generate_x25519,
    load_private_key,
    sign,
    verify,
    write_key_pair,
)


def measure(name: str, fn: Callable[[], Any], runs: int) -> dict[str, Any]:
    """Time ``fn`` ``runs`` times and summarise.

    Reports the median rather than the mean: these operations have occasional
    long tails (prime search, page cache misses) that drag a mean around
    without saying anything useful about typical cost.
    """
    samples: list[float] = []
    for _ in range(runs):
        start = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - start)

    samples.sort()
    return {
        "name": name,
        "runs": runs,
        "median_ms": statistics.median(samples) * 1000,
        "min_ms": samples[0] * 1000,
        "max_ms": samples[-1] * 1000,
    }


def build_cases(quick: bool) -> list[tuple[str, Callable[[], Any], int]]:
    """Assemble the benchmark set with its fixtures pre-built."""
    scale = 3 if quick else 1

    rsa2048 = generate_rsa(key_size=2048)
    ed = generate_ed25519()
    ec = generate_ecdsa(curve="p256")
    public = rsa2048.public_key()

    # Post-quantum. These are the algorithms NIST permits past 2035, so their
    # cost relative to the classical ones is the interesting number.
    kem = generate_mlkem(level=768)
    kem_public = kem.public_key()
    dsa = generate_mldsa(level=65)
    xk = generate_x25519()
    x_public = xk.public_key()

    small = b"a database password"
    medium = b"x" * (64 * 1024)
    large = b"x" * (1024 * 1024)

    small_blob = encrypt(public, small)
    medium_blob = encrypt(public, medium)
    large_blob = encrypt(public, large)

    rsa_sig = sign(rsa2048, medium)
    ed_sig = sign(ed, medium)
    ec_sig = sign(ec, medium)

    encrypted_pem = encode_private_key(rsa2048, passphrase=b"benchmark passphrase")
    plain_pem = encode_private_key(rsa2048)

    tmp = Path(tempfile.mkdtemp(prefix="encryption-helper-bench-"))
    counter = {"n": 0}

    def write_pair() -> None:
        counter["n"] += 1
        write_key_pair(ed, tmp, name=f"bench{counter['n']}")

    return [
        # Key generation. RSA dominates everything else by orders of magnitude.
        ("keygen rsa-2048", lambda: generate_rsa(key_size=2048), max(1, 5 // scale)),
        ("keygen rsa-3072", lambda: generate_rsa(key_size=3072), max(1, 3 // scale)),
        ("keygen ed25519", generate_ed25519, max(5, 200 // scale)),
        (
            "keygen ecdsa-p256",
            lambda: generate_ecdsa(curve="p256"),
            max(5, 200 // scale),
        ),
        # Envelope encryption. Cost should be dominated by AES, i.e. roughly
        # linear in payload size, with a constant RSA-OAEP wrap on top.
        ("encrypt 19 B", lambda: encrypt(public, small), max(5, 200 // scale)),
        ("encrypt 64 KiB", lambda: encrypt(public, medium), max(5, 100 // scale)),
        ("encrypt 1 MiB", lambda: encrypt(public, large), max(3, 30 // scale)),
        ("decrypt 19 B", lambda: decrypt(rsa2048, small_blob), max(5, 100 // scale)),
        ("decrypt 64 KiB", lambda: decrypt(rsa2048, medium_blob), max(5, 60 // scale)),
        ("decrypt 1 MiB", lambda: decrypt(rsa2048, large_blob), max(3, 20 // scale)),
        # Post-quantum encryption. ML-KEM encapsulation is fast; the
        # ciphertext overhead (1088 B vs RSA's 256 B) is the real cost.
        ("keygen mlkem-768", lambda: generate_mlkem(level=768), max(5, 100 // scale)),
        (
            "keygen mlkem-1024",
            lambda: generate_mlkem(level=1024),
            max(5, 100 // scale),
        ),
        ("keygen mldsa-65", lambda: generate_mldsa(level=65), max(5, 100 // scale)),
        ("keygen x25519", generate_x25519, max(5, 200 // scale)),
        (
            "encrypt mlkem 64KiB",
            lambda: encrypt(kem_public, medium),
            max(5, 60 // scale),
        ),
        (
            "decrypt mlkem 64KiB",
            lambda: decrypt(kem, encrypt(kem_public, medium)),
            max(3, 30 // scale),
        ),
        (
            "encrypt x25519 64KiB",
            lambda: encrypt(x_public, medium),
            max(5, 60 // scale),
        ),
        ("sign mldsa-65", lambda: sign(dsa, medium), max(5, 60 // scale)),
        (
            "verify mldsa-65",
            lambda: verify(dsa.public_key(), sign(dsa, medium), medium),
            max(3, 30 // scale),
        ),
        # Signatures over 64 KiB.
        ("sign rsa-pss", lambda: sign(rsa2048, medium), max(5, 100 // scale)),
        ("sign ed25519", lambda: sign(ed, medium), max(5, 200 // scale)),
        ("sign ecdsa-p256", lambda: sign(ec, medium), max(5, 200 // scale)),
        (
            "verify rsa-pss",
            lambda: verify(public, rsa_sig, medium),
            max(5, 200 // scale),
        ),
        (
            "verify ed25519",
            lambda: verify(ed.public_key(), ed_sig, medium),
            max(5, 200 // scale),
        ),
        (
            "verify ecdsa-p256",
            lambda: verify(ec.public_key(), ec_sig, medium),
            max(5, 200 // scale),
        ),
        # Serialisation. The encrypted path runs a KDF, so it is deliberately
        # and necessarily far slower than the plaintext path.
        ("serialise plain", lambda: encode_private_key(rsa2048), max(5, 200 // scale)),
        (
            "serialise encrypted",
            lambda: encode_private_key(rsa2048, passphrase=b"benchmark passphrase"),
            max(3, 20 // scale),
        ),
        ("load plain pem", lambda: load_private_key(plain_pem), max(5, 100 // scale)),
        (
            "load encrypted pem",
            lambda: load_private_key(encrypted_pem, passphrase=b"benchmark passphrase"),
            max(3, 20 // scale),
        ),
        # Fingerprints should be trivially cheap; if they are not, something
        # is re-serialising more than it needs to.
        ("fingerprint", lambda: fingerprint_sha256(public), max(5, 200 // scale)),
        # The full storage transaction: serialise, validate the pair, write
        # two files atomically.
        ("write_key_pair", write_pair, max(3, 30 // scale)),
    ]


def main(argv: list[str] | None = None) -> int:
    """Run the benchmark set and print a table or JSON."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="Fewer iterations.")
    parser.add_argument("--json", action="store_true", help="Machine-readable output.")
    parser.add_argument("--filter", metavar="TEXT", help="Only cases matching TEXT.")
    args = parser.parse_args(argv)

    cases = build_cases(args.quick)
    if args.filter:
        cases = [c for c in cases if args.filter in c[0]]
        if not cases:
            print(f"no benchmark matches {args.filter!r}", file=sys.stderr)
            return 2

    results = []
    if not args.json:
        print(f"{'benchmark':<22} {'runs':>5} {'median':>10} {'min':>10} {'max':>10}")
        print("-" * 61)

    for name, fn, runs in cases:
        record = measure(name, fn, runs)
        results.append(record)
        if not args.json:
            print(
                f"{record['name']:<22} {record['runs']:>5} "
                f"{record['median_ms']:>9.3f}ms {record['min_ms']:>9.3f}ms "
                f"{record['max_ms']:>9.3f}ms"
            )

    if args.json:
        print(json.dumps({"benchmarks": results}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
