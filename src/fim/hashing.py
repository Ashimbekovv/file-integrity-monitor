"""Streaming hashes with checks for concurrent changes (POSIX)."""

import hashlib
import os
import stat
from pathlib import Path


class UnstableFileError(OSError):
    """A file changed while it was being read."""


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def hash_file(path: Path | str, *, dir_fd: int | None = None) -> str:
    """Hash a regular file without following its final symlink component.

    The scanner supplies an anchored directory descriptor for safe traversal.
    """
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise OSError("Not a regular file")
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        after = os.fstat(fd)
        current = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
        if _identity(before) != _identity(after) or _identity(after) != _identity(current):
            raise UnstableFileError(f"File changed during reading: {path}")
        return digest.hexdigest()
    finally:
        os.close(fd)
