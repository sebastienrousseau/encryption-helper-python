# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Tests for the on-disk cryptographic inventory.

A scanner that walks a directory tree chosen by someone else has to survive
what it finds there: symbolic links pointing out of the tree, named pipes
that would block a read, and files large enough to exhaust memory. Those
cases are tested here alongside classification, because a scan that hangs or
escapes its root is a worse failure than one that misclassifies a file.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from encryption_helper import (
    encode_private_key,
    encode_public_key,
    encrypt,
    generate,
)
from encryption_helper.inventory import (
    KIND_CERTIFICATE,
    KIND_CONTAINER,
    KIND_ENCRYPTED_PRIVATE_KEY,
    KIND_PRIVATE_KEY,
    KIND_PUBLIC_KEY,
    MAX_CANDIDATE_BYTES,
    classify,
    scan,
    summarise,
)

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="needs POSIX symlink and FIFO semantics"
)


def _certificate(tmp_path, key, subject="payments.example.com"):
    """Write a self-signed certificate over ``key`` and return its path."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
        .not_valid_after(dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "tls.crt"
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


class TestClassification:
    def test_a_public_key_is_assessed(self, tmp_path):
        key = generate("ed25519")
        path = tmp_path / "signing.pub"
        path.write_bytes(encode_public_key(key.public_key()))
        finding = classify(path)
        assert finding is not None
        assert finding.kind == KIND_PUBLIC_KEY
        assert finding.algorithm == "ed25519"
        assert finding.replacements == ("mldsa",)

    def test_an_unprotected_private_key_is_assessed(self, tmp_path):
        key = generate("rsa", key_size=2048)
        path = tmp_path / "service.pem"
        path.write_bytes(encode_private_key(key, passphrase=None))
        finding = classify(path)
        assert finding is not None
        assert finding.kind == KIND_PRIVATE_KEY
        assert finding.algorithm == "rsa"
        assert finding.key_size == 2048

    def test_an_encrypted_private_key_is_reported_undetermined(self, tmp_path):
        """The algorithm is inside the encrypted structure.

        The honest answer is that it cannot be read, not that it is absent.
        """
        key = generate("rsa", key_size=2048)
        path = tmp_path / "protected.pem"
        path.write_bytes(encode_private_key(key, passphrase=b"a-long-passphrase"))
        finding = classify(path)
        assert finding is not None
        assert finding.kind == KIND_ENCRYPTED_PRIVATE_KEY
        assert finding.algorithm is None
        assert finding.undetermined is True

    def test_an_encrypted_private_key_still_needs_attention(self, tmp_path):
        """A gate must not pass a key merely because it is well protected.

        ``action_required`` is false only because the algorithm is unknown.
        Treating that as a clean result would let an RSA-2048 key through for
        the sole reason that it had a passphrase.
        """
        key = generate("rsa", key_size=2048)
        path = tmp_path / "protected.pem"
        path.write_bytes(encode_private_key(key, passphrase=b"a-long-passphrase"))
        finding = classify(path)
        assert finding is not None
        assert finding.action_required is False
        assert finding.needs_attention is True

    def test_a_certificate_is_assessed_and_named_by_subject(self, tmp_path):
        """A certificate is identified by subject, not by filename."""
        path = _certificate(tmp_path, generate("ecdsa"))
        finding = classify(path)
        assert finding is not None
        assert finding.kind == KIND_CERTIFICATE
        assert finding.algorithm == "ecdsa"
        assert finding.subject is not None
        assert "payments.example.com" in finding.subject

    def test_a_container_is_assessed_from_its_header(self, tmp_path):
        key = generate("rsa", key_size=2048)
        path = tmp_path / "data.enc"
        path.write_bytes(encrypt(key.public_key(), b"payload"))
        finding = classify(path)
        assert finding is not None
        assert finding.kind == KIND_CONTAINER
        assert finding.algorithm == "rsa-oaep-sha256"
        assert finding.quantum_vulnerable is True

    def test_a_post_quantum_container_needs_no_migration(self, tmp_path):
        key = generate("mlkem")
        path = tmp_path / "data.enc"
        path.write_bytes(encrypt(key.public_key(), b"payload"))
        finding = classify(path)
        assert finding is not None
        assert finding.action_required is False
        assert finding.needs_attention is False

    def test_an_unrelated_file_is_not_a_finding(self, tmp_path):
        """A scan of a working directory would otherwise be mostly noise."""
        path = tmp_path / "notes.txt"
        path.write_text("nothing cryptographic here")
        assert classify(path) is None

    def test_classification_ignores_the_filename(self, tmp_path):
        """Key material is routinely stored with a local naming convention."""
        key = generate("mlkem")
        path = tmp_path / "no-extension-at-all"
        path.write_bytes(encode_public_key(key.public_key()))
        finding = classify(path)
        assert finding is not None
        assert finding.algorithm == "mlkem"
        assert finding.key_size == 768

    def test_an_unreadable_file_is_skipped_not_fatal(self, tmp_path):
        """Permission errors are normal in a real tree."""
        assert classify(tmp_path / "does-not-exist") is None

    def test_a_private_key_banner_that_does_not_parse_is_flagged(self, tmp_path):
        path = tmp_path / "truncated.pem"
        path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nnot base64 at all\n")
        finding = classify(path)
        assert finding is not None
        assert finding.kind == KIND_PRIVATE_KEY
        assert finding.undetermined is True
        assert "could not be parsed" in finding.detail


class TestScanHazards:
    """What a scanner must survive in a directory it did not create."""

    @posix_only
    def test_a_symlink_to_another_tree_is_not_followed(self, tmp_path):
        """Otherwise a planted link turns one scan into a filesystem scan."""
        inside = tmp_path / "inside"
        inside.mkdir()
        outside = tmp_path / "outside"
        outside.mkdir()
        key = generate("ed25519")
        (outside / "elsewhere.pub").write_bytes(encode_public_key(key.public_key()))
        (inside / "escape").symlink_to(outside)

        assert scan([inside]) == []

    @posix_only
    def test_a_symlinked_file_is_not_counted_twice(self, tmp_path):
        key = generate("ed25519")
        real = tmp_path / "real.pub"
        real.write_bytes(encode_public_key(key.public_key()))
        (tmp_path / "alias.pub").symlink_to(real)

        findings = scan([tmp_path])
        assert [f.path.name for f in findings] == ["real.pub"]

    @posix_only
    def test_a_named_pipe_does_not_block_the_scan(self, tmp_path):
        """Reading a FIFO with no writer blocks forever."""
        os.mkfifo(tmp_path / "pipe")
        key = generate("ed25519")
        (tmp_path / "real.pub").write_bytes(encode_public_key(key.public_key()))

        findings = scan([tmp_path])
        assert [f.path.name for f in findings] == ["real.pub"]

    def test_a_large_file_is_read_only_up_to_the_limit(self, tmp_path):
        """A data file beginning like a certificate must not be read whole."""
        path = tmp_path / "huge.bin"
        path.write_bytes(
            b"-----BEGIN CERTIFICATE-----\n" + b"A" * (MAX_CANDIDATE_BYTES * 3)
        )
        assert classify(path) is None

    @posix_only
    def test_a_symlinked_directory_below_the_root_is_pruned(self, tmp_path):
        nested = tmp_path / "a" / "b"
        nested.mkdir(parents=True)
        outside = tmp_path / "outside"
        outside.mkdir()
        key = generate("ed25519")
        (outside / "elsewhere.pub").write_bytes(encode_public_key(key.public_key()))
        (nested / "link").symlink_to(outside)

        assert scan([tmp_path / "a"]) == []


class TestScan:
    def test_a_single_file_can_be_scanned_directly(self, tmp_path):
        key = generate("ed25519")
        path = tmp_path / "signing.pub"
        path.write_bytes(encode_public_key(key.public_key()))
        assert len(scan([path])) == 1

    def test_results_are_ordered_so_two_runs_can_be_diffed(self, tmp_path):
        for name in ("c", "a", "b"):
            key = generate("ed25519")
            (tmp_path / f"{name}.pub").write_bytes(encode_public_key(key.public_key()))
        paths = [str(f.path) for f in scan([tmp_path])]
        assert paths == sorted(paths)

    def test_nested_directories_are_walked(self, tmp_path):
        deep = tmp_path / "a" / "b" / "c"
        deep.mkdir(parents=True)
        key = generate("ed25519")
        (deep / "signing.pub").write_bytes(encode_public_key(key.public_key()))
        assert len(scan([tmp_path])) == 1

    def test_an_empty_path_list_is_not_an_error(self):
        assert scan([]) == []

    def test_a_missing_path_is_not_an_error(self, tmp_path):
        """A scan reports what it can see rather than failing on the first gap."""
        assert scan([tmp_path / "absent"]) == []


class TestSummary:
    def test_counts_match_the_findings(self, tmp_path):
        vulnerable = generate("rsa", key_size=2048)
        (tmp_path / "legacy.pub").write_bytes(
            encode_public_key(vulnerable.public_key())
        )
        (tmp_path / "protected.pem").write_bytes(
            encode_private_key(vulnerable, passphrase=b"a-long-passphrase")
        )
        modern = generate("mlkem")
        (tmp_path / "modern.pub").write_bytes(encode_public_key(modern.public_key()))

        summary = summarise(scan([tmp_path]))
        assert summary["examined"] == 3
        assert summary["action_required"] == 1
        assert summary["undetermined"] == 1
        assert summary["needs_attention"] == 2
        assert summary["quantum_vulnerable"] == 1

    def test_an_empty_scan_summarises_to_zero(self):
        summary = summarise([])
        assert summary["examined"] == 0
        assert summary["action_required"] == 0
        assert summary["by_kind"] == {}

    def test_by_kind_is_sorted_for_stable_output(self, tmp_path):
        key = generate("rsa", key_size=2048)
        (tmp_path / "a.pub").write_bytes(encode_public_key(key.public_key()))
        (tmp_path / "b.enc").write_bytes(encrypt(key.public_key(), b"x"))
        by_kind = summarise(scan([tmp_path]))["by_kind"]
        assert list(by_kind) == sorted(by_kind)

    def test_findings_are_json_serialisable(self, tmp_path):
        key = generate("rsa", key_size=2048)
        (tmp_path / "legacy.pub").write_bytes(encode_public_key(key.public_key()))
        payload = json.dumps([f.as_dict() for f in scan([tmp_path])])
        assert json.loads(payload)[0]["algorithm"] == "rsa"


class TestFindingsCarryNoSecrets:
    """A report is shared more widely than the keys it describes."""

    def test_an_unprotected_private_key_is_not_quoted_in_the_finding(self, tmp_path):
        key = generate("rsa", key_size=2048)
        pem = encode_private_key(key, passphrase=None)
        path = tmp_path / "service.pem"
        path.write_bytes(pem)

        finding = classify(path)
        assert finding is not None
        rendered = json.dumps(finding.as_dict())
        assert "PRIVATE KEY" not in rendered
        assert "BEGIN" not in rendered
        for line in pem.decode().splitlines()[1:-1]:
            if len(line) > 20:
                assert line not in rendered


class TestUnrecognisedKeyTypes:
    """A key type outside this library's range must be reported, not ignored.

    Silently dropping it would under-report an inventory, which is the one
    failure mode a migration scan must not have.
    """

    def test_a_dsa_public_key_is_reported_as_undetermined(self, tmp_path):
        from cryptography.hazmat.primitives.asymmetric import dsa

        key = dsa.generate_private_key(key_size=2048)
        path = tmp_path / "legacy-dsa.pub"
        path.write_bytes(
            key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        finding = classify(path)
        assert finding is not None
        assert finding.kind == KIND_PUBLIC_KEY
        assert finding.algorithm is None
        assert finding.undetermined is True
        assert finding.needs_attention is True
        assert "not one this library assesses" in finding.detail

    def test_a_scan_skips_unrecognised_files_but_keeps_the_rest(self, tmp_path):
        """Exercises the walk continuing past a file that is not a finding."""
        (tmp_path / "README.txt").write_text("documentation")
        (tmp_path / "data.bin").write_bytes(b"\x00\x01\x02\x03")
        key = generate("mlkem")
        (tmp_path / "real.pub").write_bytes(encode_public_key(key.public_key()))

        findings = scan([tmp_path])
        assert [f.path.name for f in findings] == ["real.pub"]
