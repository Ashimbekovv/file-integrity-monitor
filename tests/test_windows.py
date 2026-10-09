"""Native Windows security checks; executed by the Windows CI runner."""

import os
import subprocess

import pytest

from fim.hashing import hash_file
from fim.scanner import scan_directory

pytestmark = pytest.mark.skipif(os.name != "nt", reason="Native Windows handles required")


def make_junction(link, target):
    result = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(target)],
                            capture_output=True)
    assert result.returncode == 0, result.stderr


def test_junction_does_not_read_external_files(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("do not read")
    link = root / "junction"
    make_junction(link, outside)
    try:
        result = scan_directory(root)
        assert not result.errors
        assert not result.hashes
    finally:
        link.rmdir()


def test_file_hash_rejects_junction_ancestor(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("do not read")
    link = tmp_path / "junction"
    make_junction(link, outside)
    try:
        with pytest.raises(OSError, match="reparse point"):
            hash_file(link / "secret")
    finally:
        link.rmdir()


def test_pinned_directory_cannot_be_replaced(tmp_path):
    from fim.windows_io import pin_directory

    root = tmp_path / "root"
    root.mkdir()
    with pin_directory(root):
        with pytest.raises(OSError):
            root.rename(tmp_path / "moved")
        assert root.is_dir()
    root.rename(tmp_path / "moved")


def test_pinned_file_cannot_be_replaced(tmp_path):
    from fim.windows_io import open_file_fd

    path = tmp_path / "file"
    path.write_text("original")
    fd = open_file_fd(path)
    try:
        with pytest.raises(OSError):
            path.unlink()
        assert os.read(fd, 100) == b"original"
    finally:
        os.close(fd)
    path.unlink()


def test_binary_mode_preserves_crlf_and_control_z(tmp_path):
    import hashlib

    path = tmp_path / "binary"
    data = b"first\r\n\x1asecond\x00"
    path.write_bytes(data)
    assert hash_file(path) == hashlib.sha256(data).hexdigest()


def test_symlink_swapped_after_listing_is_rejected(tmp_path, monkeypatch, make_symlink):
    from fim import windows_io

    root = tmp_path / "root"
    root.mkdir()
    path = root / "file"
    path.write_text("original")
    outside = tmp_path / "secret"
    outside.write_text("secret")
    original_open = windows_io.open_file_fd
    def swap_then_open(target):
        if target == path:
            path.unlink()
            make_symlink(path, outside)
        return original_open(target)
    monkeypatch.setattr(windows_io, "open_file_fd", swap_then_open)
    result = scan_directory(root)
    assert not result.hashes
    assert "file" in result.errors
