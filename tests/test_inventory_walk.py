# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""The scan's walk: what it reads, what it reports, and what it cannot hang on.

A migration-readiness gate is only as good as its coverage. Before these
checks an unreadable file or directory was dropped without trace -- so
``scan --fail-on-finding`` passed over a key it could not open -- a FIFO
swapped in after the walk saw a regular file stalled the scan, and a deep
tree raised ``RecursionError`` on Python 3.10 and 3.11.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading

import pytest
from encryption_helper import encode_public_key, generate
from encryption_helper.cli import main
from encryption_helper.inventory import (
    KIND_UNREADABLE,
    _classify,
    scan,
    summarise,
)

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX semantics")
needs_unprivileged = pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="root reads mode-000 files regardless",
)

EXIT_FINDINGS = 5


def _public_key(path):
    path.write_bytes(encode_public_key(generate("ed25519").public_key()))


@needs_unprivileged
class TestNothingIsSkippedSilently:
    def test_an_unreadable_file_is_a_finding_needing_attention(self, tmp_path):
        locked = tmp_path / "locked.pem"
        _public_key(locked)
        locked.chmod(0)
        try:
            (finding,) = scan([tmp_path])
        finally:
            locked.chmod(0o600)
        assert finding.kind == KIND_UNREADABLE
        assert finding.needs_attention
        assert "could not be read" in finding.detail

    def test_an_unlistable_directory_is_a_finding(self, tmp_path):
        sealed = tmp_path / "sealed"
        sealed.mkdir()
        _public_key(sealed / "inside.pub")
        sealed.chmod(0)
        try:
            (finding,) = scan([tmp_path])
        finally:
            sealed.chmod(0o700)
        assert finding.kind == KIND_UNREADABLE
        assert finding.path == sealed
        assert "could not be listed" in finding.detail

    def test_the_gate_fails_on_what_it_could_not_read(self, tmp_path):
        locked = tmp_path / "locked.pem"
        _public_key(locked)
        locked.chmod(0)
        try:
            code = main(["-q", "scan", "--fail-on-finding", str(tmp_path)])
        finally:
            locked.chmod(0o600)
        assert code == EXIT_FINDINGS

    def test_the_summary_counts_it_as_undetermined(self, tmp_path):
        locked = tmp_path / "locked.pem"
        _public_key(locked)
        locked.chmod(0)
        try:
            summary = summarise(scan([tmp_path]))
        finally:
            locked.chmod(0o600)
        assert summary["undetermined"] == 1
        assert summary["needs_attention"] == 1
        assert summary["by_kind"] == {KIND_UNREADABLE: 1}


@posix_only
class TestNothingCanBlockTheScan:
    def test_a_fifo_swapped_in_after_the_walk_does_not_block(self, tmp_path):
        """The walk saw a regular file; by the time it is opened, a FIFO."""
        fifo = tmp_path / "swapped"
        os.mkfifo(fifo)
        result: list[object] = []
        worker = threading.Thread(target=lambda: result.append(_classify(fifo)))
        worker.daemon = True
        worker.start()
        worker.join(10)
        assert not worker.is_alive(), "opening a FIFO blocked the scan"
        assert result == [None]

    def test_a_link_swapped_in_after_the_walk_is_not_read(self, tmp_path):
        real = tmp_path / "real.pub"
        _public_key(real)
        link = tmp_path / "link.pub"
        link.symlink_to(real)
        with pytest.raises(OSError):  # noqa: PT011 - ELOOP's errno varies by OS
            _classify(link)


@posix_only
def test_a_deep_tree_does_not_exhaust_the_stack(tmp_path):
    """os.walk recursed on 3.10 and 3.11; the walk is now iterative.

    Run in a child with a low recursion limit, so the test is fast and
    portable instead of needing a tree deeper than the default limit.
    """
    depth = 300
    leaf = tmp_path
    for _ in range(depth):
        leaf = leaf / "d"
    leaf.mkdir(parents=True)
    _public_key(leaf / "deep.pub")
    program = textwrap.dedent(
        f"""
        import sys
        from encryption_helper.inventory import scan
        sys.setrecursionlimit(200)
        print(len(scan([{str(tmp_path)!r}])))
        """
    )
    completed = subprocess.run(  # noqa: S603
        [sys.executable, "-c", program],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip() == "1"


class TestRoots:
    @posix_only
    def test_a_named_symlinked_directory_is_scanned(self, tmp_path):
        """A path the caller names is taken as given."""
        real = tmp_path / "real"
        real.mkdir()
        _public_key(real / "k.pub")
        (tmp_path / "alias").symlink_to(real)
        assert len(scan([tmp_path / "alias"])) == 1

    @posix_only
    def test_a_named_symlinked_file_is_scanned_too(self, tmp_path):
        """It used to be skipped silently, unlike a symlinked directory."""
        real = tmp_path / "k.pub"
        _public_key(real)
        alias = tmp_path / "alias.pub"
        alias.symlink_to(real)
        assert len(scan([alias])) == 1

    @posix_only
    def test_links_beneath_a_root_are_still_not_followed(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        _public_key(outside / "k.pub")
        root = tmp_path / "root"
        root.mkdir()
        (root / "escape").symlink_to(outside)
        (root / "file-link.pub").symlink_to(outside / "k.pub")
        assert scan([root]) == []

    def test_output_order_is_stable(self, tmp_path):
        for name in ("b.pub", "a.pub", "c.pub"):
            _public_key(tmp_path / name)
        assert [f.path.name for f in scan([tmp_path])] == ["a.pub", "b.pub", "c.pub"]
