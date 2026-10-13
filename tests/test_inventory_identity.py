# SPDX-License-Identifier: Apache-2.0
# Copyright 2024-2026 HSBC Group Management Services Limited
"""A scan reads what its walk found, not whatever the path names later.

``O_NOFOLLOW`` protects only the last component of a path. Between the walk
listing ``root/sub`` and the scan reading inside it, someone with write
access to the tree could replace ``sub`` with a symlink to a directory
outside it, and the scan classified files there as if they were under the
root: through the MCP server, a way to learn about files outside its
``--root``. Each entry's identity (device and inode) is now recorded when
the walk finds it and confirmed when it is opened.
"""

from __future__ import annotations

import shutil
import sys

import pytest
from encryption_helper import _platform, encode_private_key, generate, inventory
from encryption_helper.inventory import KIND_UNREADABLE, scan

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="needs POSIX symlinks and descriptors"
)


@pytest.fixture
def tree(tmp_path):
    """``root/{a.txt, sub/x.pem}``, and ``outside/x.pem`` holding a real key."""
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("a")
    (root / "sub" / "x.pem").write_text("not a key")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.pem").write_bytes(encode_private_key(generate("ed25519")))
    return root, outside


def _swap_when_classifying(monkeypatch, name, swap):
    """Run ``swap`` once, just before the scan reads the file called ``name``."""
    real = inventory._classify
    done = []

    def spy(path, *args, **kwargs):
        if path.name == name and not done:
            done.append(True)
            swap()
        return real(path, *args, **kwargs)

    monkeypatch.setattr(inventory, "_classify", spy)


@posix_only
class TestSwappedDirectories:
    def test_a_directory_swapped_for_a_link_is_not_listed(self, tree, monkeypatch):
        root, outside = tree

        def swap():
            shutil.rmtree(root / "sub")
            (root / "sub").symlink_to(outside)

        _swap_when_classifying(monkeypatch, "a.txt", swap)
        findings = scan([root])
        assert not any(f.kind == "private-key" for f in findings), findings
        (changed,) = [f for f in findings if f.path == root / "sub"]
        assert changed.kind == KIND_UNREADABLE
        assert "changed while" in changed.detail

    def test_a_parent_swapped_under_a_pending_file_is_caught(
        self, tree, monkeypatch, tmp_path
    ):
        """The file's own name is not a link, so only its identity tells."""
        root, outside = tree
        # Files are read in reverse name order, so z.txt comes before x.pem.
        (root / "sub" / "z.txt").write_text("z")

        def swap():
            (root / "sub").rename(tmp_path / "parked")
            (root / "sub").symlink_to(outside)

        _swap_when_classifying(monkeypatch, "z.txt", swap)
        findings = scan([root])
        assert not any(f.kind == "private-key" for f in findings), findings
        (changed,) = [f for f in findings if f.path == root / "sub" / "x.pem"]
        assert changed.kind == KIND_UNREADABLE
        assert "changed while" in changed.detail

    def test_a_grandparent_swapped_above_a_pending_directory_is_caught(
        self, tmp_path, monkeypatch
    ):
        """``root/a/b`` is queued; then ``root/a`` becomes a link elsewhere.

        Opening ``root/a/b`` no-follow checks only ``b``, which is a real
        directory in the other tree. Only its identity shows it is not the
        directory the walk found.
        """
        root = tmp_path / "root"
        (root / "a" / "b").mkdir(parents=True)
        (root / "a" / "z.txt").write_text("z")
        elsewhere = tmp_path / "elsewhere"
        (elsewhere / "b").mkdir(parents=True)
        (elsewhere / "b" / "k.pem").write_bytes(encode_private_key(generate("ed25519")))

        def swap():
            (root / "a").rename(tmp_path / "parked")
            (root / "a").symlink_to(elsewhere)

        _swap_when_classifying(monkeypatch, "z.txt", swap)
        findings = scan([root])
        assert not any(f.kind == "private-key" for f in findings), findings
        (changed,) = [f for f in findings if f.path == root / "a" / "b"]
        assert "changed while" in changed.detail

    def test_an_unchanged_tree_is_scanned_as_before(self, tree):
        root, _ = tree
        assert [f.path for f in scan([root])] == []

    def test_a_root_given_as_a_link_is_still_followed(self, tree, tmp_path):
        """The caller named the root; only links found beneath it are refused."""
        _, outside = tree
        link = tmp_path / "named-root"
        link.symlink_to(outside)
        (finding,) = scan([link])
        assert finding.kind == "private-key"


class TestLoops:
    def test_a_directory_already_walked_is_not_walked_again(
        self, tmp_path, monkeypatch
    ):
        """A bind mount or a junction can lead back into the tree.

        Links are not followed, but those are not links. Every directory is
        walked at most once by identity, so a loop costs one visit.
        """
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        (tmp_path / "a" / "k.txt").write_text("x")
        (tmp_path / "b" / "k.txt").write_text("x")
        real = _platform.entry_identity
        same = (-1, -1)

        def collide(entry, parent):
            if entry.name in {"a", "b"}:
                return same
            return real(entry, parent)

        monkeypatch.setattr(_platform, "entry_identity", collide)
        listed = []
        real_open = _platform.open_directory

        def spy(path, expected, *, follow):
            listed.append(path.name)
            return real_open(path, None, follow=follow)

        monkeypatch.setattr(_platform, "open_directory", spy)
        scan([tmp_path])
        assert sorted(listed) in (
            sorted([tmp_path.name, "a"]),
            sorted([tmp_path.name, "b"]),
        )
