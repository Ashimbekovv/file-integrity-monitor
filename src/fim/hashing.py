"""Streaming hashes with checks for concurrent changes on POSIX and Windows."""

import hashlib
import os
import stat
from pathlib import Path
from contextlib import ExitStack


class UnstableFileError(OSError):
    """A file changed while it was being read."""


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def hash_file(path: Path | str, *, dir_fd: int | None = None) -> str:
    """Hash a regular file without following its final symlink component.

    The scanner supplies an anchored directory descriptor for safe traversal.
    """
    with ExitStack() as stack:
        if os.name == "nt":
            from fim.windows_io import open_file_fd, pin_directory_chain

            if dir_fd is not None:
                raise ValueError("Directory descriptors are not supported on Windows")
            path = Path(path).absolute()
            stack.enter_context(pin_directory_chain(path.parent))
            fd = open_file_fd(path)
        else:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
        stack.callback(os.close, fd)
        return _hash_open_file(fd, path, dir_fd)


def _hash_open_file(fd: int, path: Path | str, dir_fd: int | None) -> str:
    """Read a descriptor whose lifetime and ancestors are managed by caller."""
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode):
        raise OSError("Not a regular file")
    digest = hashlib.sha256()
    while chunk := os.read(fd, 1024 * 1024):
        digest.update(chunk)
    after = os.fstat(fd)
    if os.name == "nt":
        from fim.windows_io import open_file_fd

        # Use handle metadata for both reads: Windows path-stat and fstat can
        # expose different timestamp precision/cache behavior after a write.
        current_fd = open_file_fd(Path(path))
        try:
            current = os.fstat(current_fd)
        finally:
            os.close(current_fd)
    else:
        current = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
    if _identity(before) != _identity(after) or _identity(after) != _identity(current):
        raise UnstableFileError(f"File changed during reading: {path}")
    return digest.hexdigest()
