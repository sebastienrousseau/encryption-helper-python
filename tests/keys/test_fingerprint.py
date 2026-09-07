"""Tests for public key fingerprints.

The important test here is the cross-check against ``ssh-keygen``: a
fingerprint that only agrees with itself is worthless, since the whole point is
that a user can compare it with what another tool shows them.
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess

import pytest
from encryption_helper.keys import encode_public_key, fingerprint_sha256

_SSH_KEYGEN = shutil.which("ssh-keygen")

needs_ssh_keygen = pytest.mark.skipif(
    _SSH_KEYGEN is None, reason="ssh-keygen is not installed"
)


class TestFingerprintFormat:
    @pytest.mark.parametrize("fixture", ["rsa_key", "ed25519_key", "ecdsa_key"])
    def test_shape(self, request, fixture):
        fingerprint = fingerprint_sha256(request.getfixturevalue(fixture).public_key())
        assert fingerprint.startswith("SHA256:")
        # 32-byte digest -> 43 base64 characters once padding is stripped.
        assert len(fingerprint) == len("SHA256:") + 43
        assert not fingerprint.endswith("=")

    def test_is_deterministic(self, ed25519_key):
        public = ed25519_key.public_key()
        assert fingerprint_sha256(public) == fingerprint_sha256(public)

    def test_differs_between_keys(self, rsa_key, ed25519_key):
        assert fingerprint_sha256(rsa_key.public_key()) != fingerprint_sha256(
            ed25519_key.public_key()
        )

    def test_is_the_digest_of_the_openssh_blob(self, ed25519_key):
        """Independent recomputation, not a restatement of the implementation."""
        line = encode_public_key(ed25519_key.public_key(), fmt="openssh")
        blob = base64.b64decode(line.split()[1])
        expected = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        assert fingerprint_sha256(ed25519_key.public_key()) == f"SHA256:{expected}"


@needs_ssh_keygen
class TestAgainstSSHKeygen:
    @pytest.mark.parametrize("fixture", ["rsa_key", "ed25519_key", "ecdsa_key"])
    def test_matches_ssh_keygen(self, request, tmp_path, fixture):
        key = request.getfixturevalue(fixture)
        path = tmp_path / "id.pub"
        path.write_bytes(encode_public_key(key.public_key(), fmt="openssh"))

        completed = subprocess.run(  # noqa: S603
            [str(_SSH_KEYGEN), "-l", "-f", str(path)],
            capture_output=True,
            text=True,
            check=True,
        )
        # Output is "<bits> SHA256:<b64> <comment> (<type>)".
        expected = completed.stdout.split()[1]
        assert fingerprint_sha256(key.public_key()) == expected


class TestFingerprintFailures:
    def test_unencodable_key_is_reported(self, ed25519_key, monkeypatch):
        import encryption_helper.keys.fingerprint as module

        monkeypatch.setattr(module, "encode_public_key", lambda *a, **k: b"ssh-ed25519")
        with pytest.raises(Exception, match="Unexpected OpenSSH encoding"):
            module.fingerprint_sha256(ed25519_key.public_key())

    def test_undecodable_blob_is_reported(self, ed25519_key, monkeypatch):
        import encryption_helper.keys.fingerprint as module

        monkeypatch.setattr(
            module, "encode_public_key", lambda *a, **k: b"ssh-ed25519 !!!not-base64!!!"
        )
        with pytest.raises(Exception, match="Could not decode"):
            module.fingerprint_sha256(ed25519_key.public_key())
