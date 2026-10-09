import hashlib
import os
import pytest
from fim.hashing import hash_file, UnstableFileError


def test_sha256(tmp_path):
    path = tmp_path / "file"
    path.write_bytes(b"abc")
    assert hash_file(path) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_large_stream(tmp_path):
    path = tmp_path / "large"
    data = b"x" * (2 * 1024 * 1024 + 1)
    path.write_bytes(data)
    assert hash_file(path) == hashlib.sha256(data).hexdigest()


def test_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        hash_file(tmp_path / "missing")


def test_symlink(tmp_path, make_symlink):
    target = tmp_path / "target"
    target.write_text("secret")
    link = tmp_path / "link"
    make_symlink(link, target)
    with pytest.raises(OSError):
        hash_file(link)


def test_changes_during_read(tmp_path, monkeypatch):
    path = tmp_path / "file"
    path.write_bytes(b"original")
    original = os.read
    changed = False
    def changing_read(fd, size):
        nonlocal changed
        data = original(fd, size)
        if not changed:
            changed = True
            path.write_bytes(b"replacement content")
        return data
    monkeypatch.setattr(os, "read", changing_read)
    with pytest.raises(UnstableFileError):
        hash_file(path)
