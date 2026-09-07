# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""Assert the documentation describes the software that actually exists.

Version 0.0.1 shipped a README stating the private key format was PKCS#1 while
the code emitted PKCS#8, and declaring an MIT licence while the repository
carried Apache-2.0. Nothing caught either, because nothing checked. These tests
compare the prose against the implementation so a claim cannot silently rot.

They are repository-hygiene checks: they read files from the source tree, so
they skip when the suite runs against an installed wheel.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import tomllib
from encryption_helper import errors
from encryption_helper.cli import (
    EXIT_CRYPTO_FAILURE,
    EXIT_ERROR,
    EXIT_KEY_EXISTS,
    EXIT_OK,
    EXIT_USAGE,
    build_parser,
)
from encryption_helper.keys import ALLOWED_RSA_KEY_SIZES, SUPPORTED_CURVES

from ._support import source_tree_only

pytestmark = source_tree_only

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def readme() -> str:
    return (REPO / "README.md").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def changelog() -> str:
    return (REPO / "CHANGELOG.md").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def pyproject() -> dict:
    return tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))


def all_option_strings() -> set[str]:
    """Every flag the parser accepts, across all subcommands."""
    found: set[str] = set()

    def walk(parser) -> None:
        for action in parser._actions:
            found.update(action.option_strings)
            # `choices` is a dict of sub-parsers for a subcommand action,
            # but a plain tuple for a value-restricted flag such as --format.
            choices = getattr(action, "choices", None)
            if isinstance(choices, dict):
                for choice in choices.values():
                    if hasattr(choice, "_actions"):
                        walk(choice)

    walk(build_parser())
    return found


def subcommand_names() -> set[str]:
    """The names of every subcommand."""
    parser = build_parser()
    for action in parser._actions:
        choices = getattr(action, "choices", None)
        if isinstance(choices, dict) and hasattr(
            next(iter(choices.values()), None), "_actions"
        ):
            return set(choices)
    return set()  # pragma: no cover - the parser always has subcommands


class TestCliDocumentation:
    def test_every_documented_flag_exists(self, readme):
        """A README flag the parser rejects is a broken instruction."""
        documented = set(re.findall(r"`(--[a-z][a-z0-9-]*)`", readme))
        documented |= set(re.findall(r"^\s*\| `(--[a-z][a-z0-9-]*)", readme, re.M))
        missing = sorted(documented - all_option_strings())
        assert not missing, f"README documents non-existent flags: {missing}"

    def test_every_flag_in_command_examples_exists(self, readme):
        """Flags used inside `encryption-helper ...` examples must be real."""
        actual = all_option_strings()
        used: set[str] = set()
        for line in readme.splitlines():
            if "encryption-helper " in line and not line.startswith("|"):
                used.update(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", line))
        missing = sorted(used - actual)
        assert not missing, f"README examples use non-existent flags: {missing}"

    def test_every_subcommand_is_documented(self, readme):
        undocumented = sorted(
            name
            for name in subcommand_names()
            if f"encryption-helper {name}" not in readme
        )
        assert not undocumented, f"undocumented subcommands: {undocumented}"

    def test_exit_codes_match_the_implementation(self, readme):
        """The exit-code table is a contract that scripts depend on."""
        expected = {
            EXIT_OK: "success",
            EXIT_ERROR: "error",
            EXIT_USAGE: "usage",
            EXIT_KEY_EXISTS: "exists",
            EXIT_CRYPTO_FAILURE: "failed",
        }
        rows = dict(re.findall(r"^\| `(\d)` \| ([^|]+?) \|", readme, re.M))
        assert rows, "the exit-code table is missing from the README"
        for code, fragment in expected.items():
            assert str(code) in rows, f"exit code {code} is undocumented"
            assert fragment in rows[str(code)].lower(), (
                f"exit code {code} documented as {rows[str(code)]!r}, "
                f"which does not mention {fragment!r}"
            )

    def test_documented_key_sizes_match_the_allowlist(self, readme):
        documented = re.search(r"`--key-size` accepts ([^.]+)\.", readme)
        assert documented, "the --key-size allowlist is not documented"
        sizes = {int(n) for n in re.findall(r"\d{4}", documented.group(1))}
        assert sizes == set(ALLOWED_RSA_KEY_SIZES)

    def test_documented_curves_exist(self, readme):
        for curve in re.findall(r"--curve (\w+)", readme):
            assert curve in SUPPORTED_CURVES, f"README uses unknown curve {curve!r}"


class TestErrorDocumentation:
    def test_documented_errors_exist(self, readme):
        documented = set(re.findall(r"^\| `(\w+Error)` \|", readme, re.M))
        assert documented, "the error table is missing from the README"
        for name in documented:
            assert hasattr(errors, name), f"README documents unknown error {name}"

    def test_every_public_error_is_documented(self, readme):
        documented = set(re.findall(r"^\| `(\w+Error)` \|", readme, re.M))
        public = set(errors.__all__) - {"EncryptionHelperError"}
        undocumented = sorted(public - documented)
        assert not undocumented, f"undocumented public errors: {undocumented}"


class TestCryptographicClaims:
    def test_private_key_container_claim_is_accurate(self, readme, ed25519_key):
        """Regression: 0.0.1's README said PKCS#1; the code emitted PKCS#8."""
        from encryption_helper import encode_private_key

        assert "PKCS#8" in readme, "the private key container is not documented"
        assert "PKCS#1" not in readme.replace("PKCS#1 v1.5", ""), (
            "README still claims PKCS#1 for the private key container"
        )
        assert encode_private_key(ed25519_key).startswith(
            b"-----BEGIN PRIVATE KEY-----"
        )

    def test_public_key_container_claim_is_accurate(self, readme, ed25519_key):
        from encryption_helper import encode_public_key

        assert "SubjectPublicKeyInfo" in readme
        assert encode_public_key(ed25519_key.public_key()).startswith(
            b"-----BEGIN PUBLIC KEY-----"
        )

    def test_documented_default_rsa_size_matches(self, readme):
        from encryption_helper.keys import DEFAULT_RSA_KEY_SIZE

        assert str(DEFAULT_RSA_KEY_SIZE) in readme, (
            "the default RSA size in the README does not match the code"
        )

    def test_aead_and_kem_claims_match_the_implementation(self, readme):
        from encryption_helper.crypto import envelope

        assert "AES-256-GCM" in readme
        assert "RSA-OAEP" in readme
        assert envelope._CONTENT_KEY_SIZE * 8 == 256
        assert envelope._NONCE_SIZE == 12


class TestLicenceConsistency:
    def test_licence_file_is_apache(self):
        assert "Apache License" in (REPO / "LICENSE").read_text(encoding="utf-8")

    def test_metadata_declares_apache(self, pyproject):
        assert pyproject["project"]["license"] == "Apache-2.0"

    def test_readme_declares_apache_and_not_mit(self, readme):
        assert "Apache License, Version 2.0" in readme
        assert "MIT" not in readme, "README still references MIT"

    def test_every_source_file_carries_the_apache_header(self):
        result = subprocess.run(
            ["git", "grep", "-lF", "SPDX-License-Identifier:", "--", "*.py"],
            capture_output=True,
            text=True,
            check=False,
            cwd=REPO,
        )
        files = result.stdout.split()
        assert files, "no SPDX headers found"
        for name in files:
            header = (REPO / name).read_text(encoding="utf-8")[:200]
            assert "SPDX-License-Identifier: Apache-2.0" in header, name


class TestVersionConsistency:
    def test_readme_python_requirement_matches_metadata(self, readme, pyproject):
        minimum = pyproject["project"]["requires-python"].lstrip(">=")
        assert f"Python {minimum}" in readme, (
            f"README does not state the actual minimum, {minimum}"
        )

    def test_changelog_documents_the_current_version(self, changelog, pyproject):
        version = pyproject["project"]["version"]
        assert f"## [{version}]" in changelog

    def test_classifiers_cover_the_supported_range(self, pyproject):
        minor_min = int(
            pyproject["project"]["requires-python"].lstrip(">=").split(".")[1]
        )
        classified = {
            int(c.rsplit(".", 1)[1])
            for c in pyproject["project"]["classifiers"]
            if c.startswith("Programming Language :: Python :: 3.")
        }
        assert min(classified) == minor_min
        assert classified == set(range(minor_min, max(classified) + 1))


class TestExamplesAndLinks:
    @pytest.mark.parametrize(
        "example", sorted(p.name for p in (REPO / "examples").glob("*.py"))
    )
    def test_example_runs_successfully(self, example):
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(REPO / "examples" / example)],
            capture_output=True,
            text=True,
            check=False,
            cwd=REPO,
        )
        assert result.returncode == 0, (
            f"{example} failed:\n{result.stdout}\n{result.stderr}"
        )
        assert "BEGIN PRIVATE KEY" not in result.stdout
        assert "BEGIN ENCRYPTED PRIVATE KEY" not in result.stdout

    def test_readme_relative_links_resolve(self, readme):
        for path in set(re.findall(r"\]\(\./([\w./-]+)\)", readme)):
            assert (REPO / path).exists(), f"README links to missing {path}"
