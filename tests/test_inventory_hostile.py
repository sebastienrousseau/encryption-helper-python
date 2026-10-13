# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""A scan must survive what it finds, and must say when it did not look.

The inventory runs over directories nobody vetted, and through the MCP
server at the request of a model. Three failures were found in audit:

* one crafted certificate raised ``UnsupportedAlgorithm`` out of
  :func:`scan`, so a planted file suppressed the whole report;
* a root that did not exist, or was a FIFO, scanned as ``[]``, so a gate on
  ``needs_attention`` passed having examined nothing;
* nothing bounded the work, so one call could walk an arbitrarily large tree.
"""

from __future__ import annotations

import datetime as dt
import os
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.x509.oid import NameOID
from encryption_helper import encode_public_key, generate, inventory
from encryption_helper.inventory import (
    KIND_CERTIFICATE,
    KIND_PUBLIC_KEY,
    KIND_UNREADABLE,
    classify,
    scan,
    scan_report,
    summarise,
)
from encryption_helper.policy import horizon

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX FIFOs")

#: DER for the Ed25519 OID 1.3.101.112, and an unassigned sibling.
_ED25519_OID = bytes.fromhex("06032b6570")
_UNKNOWN_OID = bytes.fromhex("06032b657f")


def _certificate_with_unknown_key_type() -> bytes:
    """A well-formed certificate whose subject key type cryptography rejects.

    The key's algorithm identifier is rewritten after signing: the
    certificate still parses, and only ``public_key()`` fails.
    """
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "planted")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
        .not_valid_after(dt.datetime(2027, 1, 1, tzinfo=dt.timezone.utc))
        .sign(key, None)
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    # Occurrences: the signature algorithm, the subject key, the outer one.
    positions = [i for i in range(len(der)) if der.startswith(_ED25519_OID, i)]
    i = positions[1]
    return der[:i] + _UNKNOWN_OID + der[i + len(_ED25519_OID) :]


def _public_key_file(path):
    path.write_bytes(encode_public_key(generate("ed25519").public_key()))
    return path


class TestHostileContent:
    def test_a_certificate_with_an_unknown_key_type_is_reported(self, tmp_path):
        path = tmp_path / "planted.crt"
        path.write_bytes(_certificate_with_unknown_key_type())
        finding = classify(path)
        assert finding is not None
        assert finding.kind == KIND_CERTIFICATE
        assert finding.undetermined is True
        assert finding.needs_attention is True
        assert finding.subject == "CN=planted"

    def test_one_planted_file_does_not_suppress_the_rest(self, tmp_path):
        (tmp_path / "planted.crt").write_bytes(_certificate_with_unknown_key_type())
        _public_key_file(tmp_path / "real.pub")
        findings = scan([tmp_path])
        assert sorted(f.path.name for f in findings) == ["planted.crt", "real.pub"]

    def test_any_unexpected_failure_is_a_finding_not_an_abort(
        self, tmp_path, monkeypatch
    ):
        """Defence in depth: the next parser bug must not end a scan either."""

        def explode(path, blob):
            raise KeyError("a parser bug nobody has found yet")

        monkeypatch.setattr(inventory, "_try_container", explode)
        _public_key_file(tmp_path / "a.pub")
        (finding,) = scan([tmp_path])
        assert finding.kind == KIND_UNREADABLE
        assert finding.needs_attention is True
        assert "could not be classified" in finding.detail
        assert "KeyError" in finding.detail
        assert classify(tmp_path / "a.pub").kind == KIND_UNREADABLE


class TestRootsThatAreNotThere:
    """A root that cannot be examined is reported, never silently empty."""

    def test_a_missing_root(self, tmp_path):
        (finding,) = scan([tmp_path / "absent"])
        assert finding.kind == KIND_UNREADABLE
        assert finding.needs_attention is True
        assert summarise([finding])["needs_attention"] == 1

    @posix_only
    def test_a_dangling_symlink_root(self, tmp_path):
        link = tmp_path / "dangling"
        link.symlink_to(tmp_path / "gone")
        (finding,) = scan([link])
        assert finding.kind == KIND_UNREADABLE

    @posix_only
    def test_a_fifo_root(self, tmp_path):
        fifo = tmp_path / "pipe"
        os.mkfifo(fifo)
        (finding,) = scan([fifo])
        assert finding.kind == KIND_UNREADABLE
        assert "not a regular file or directory" in finding.detail


class TestScanReport:
    """The payload the CLI and the MCP server both return, built once."""

    def test_unbounded_is_exactly_the_cli_contract(self, tmp_path):
        _public_key_file(tmp_path / "a.pub")
        report = scan_report([tmp_path])
        assert set(report) == {"summary", "findings", "horizon"}
        assert report["horizon"] == horizon()
        assert report["summary"]["examined"] == 1
        assert report["findings"][0]["kind"] == KIND_PUBLIC_KEY

    def test_a_findings_limit_marks_the_report_truncated(self, tmp_path):
        for name in "abc":
            _public_key_file(tmp_path / f"{name}.pub")
        report = scan_report([tmp_path], limit=2)
        assert len(report["findings"]) == 2
        assert report["truncated"] is True
        assert report["summary"]["examined"] == 3
        assert "incomplete" not in report

    def test_a_file_budget_stops_the_walk_and_says_so(self, tmp_path):
        for i in range(10):
            _public_key_file(tmp_path / f"{i}.pub")
        report = scan_report([tmp_path], max_entries=4)
        assert report["summary"]["examined"] == 4
        assert "4 entries" in report["incomplete"]

    def test_a_time_budget_stops_the_walk_and_says_so(self, tmp_path, monkeypatch):
        for i in range(5):
            _public_key_file(tmp_path / f"{i}.pub")
        ticks = iter(range(100))
        monkeypatch.setattr(inventory.time, "monotonic", lambda: float(next(ticks)))
        report = scan_report([tmp_path], time_budget=2.5)
        assert report["summary"]["examined"] < 5
        assert "seconds" in report["incomplete"]

    def test_a_wide_directory_is_not_listed_past_the_budget(
        self, tmp_path, monkeypatch
    ):
        """The listing itself is bounded, not only the files classified."""
        for i in range(50):
            (tmp_path / f"{i:02}.txt").write_text("x")
        seen = []
        real = inventory._classify

        def spy(path, *args, **kwargs):
            seen.append(path)
            return real(path, *args, **kwargs)

        monkeypatch.setattr(inventory, "_classify", spy)
        report = scan_report([tmp_path], max_entries=5)
        assert len(seen) == 5
        assert "5 entries" in report["incomplete"]

    def test_the_budget_spans_every_root(self, tmp_path):
        """Several roots share one budget; a later root is not a fresh start."""
        roots = [_public_key_file(tmp_path / f"{i}.pub") for i in range(3)]
        report = scan_report(roots, max_entries=1)
        assert report["summary"]["examined"] == 1
        assert "1 entries" in report["incomplete"]

    @pytest.mark.parametrize(
        "bounds",
        [{"limit": 0}, {"max_entries": 0}, {"time_budget": 0}, {"time_budget": -1}],
    )
    def test_a_bound_that_is_not_positive_is_refused(self, tmp_path, bounds):
        from encryption_helper.errors import InvalidArgumentError

        with pytest.raises(InvalidArgumentError):
            scan_report([tmp_path], **bounds)


class TestCertificateSubject:
    def test_a_subject_that_cannot_be_rendered_still_yields_a_finding(
        self, tmp_path, monkeypatch
    ):
        """``rfc4514_string`` can raise for a malformed attribute value."""
        key = generate("ed25519")

        class _Subject:
            def rfc4514_string(self):
                raise ValueError("malformed attribute")

        class _Certificate:
            subject = _Subject()

            def public_key(self):
                return key.public_key()

        monkeypatch.setattr(
            inventory.x509, "load_pem_x509_certificate", lambda blob: _Certificate()
        )
        path = tmp_path / "odd.crt"
        path.write_text("-----BEGIN CERTIFICATE-----\n")
        finding = classify(path)
        assert finding.kind == KIND_CERTIFICATE
        assert finding.subject is None
        assert finding.algorithm == "ed25519"
