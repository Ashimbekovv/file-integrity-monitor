"""Recursive, descriptor-anchored scanning without following symlinks."""

import fnmatch
import logging
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

from fim.hashing import hash_file

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    hashes: dict[str, str] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)


def scan_directory(root: Path, excludes: list[str] | None = None) -> ScanResult:
    """Scan only root; exclusions match relative POSIX paths or basenames.

    Matching a directory prunes its entire subtree. Symlinks and special files
    are skipped. Any error makes the result incomplete and must block comparison.
    """
    root = root.resolve(strict=True)
    patterns = excludes or []
    result = ScanResult()

    def visit(directory_fd: int, prefix: str) -> None:
        try:
            with os.scandir(directory_fd) as entries:
                names = sorted(entry.name for entry in entries)
        except OSError as exc:
            result.errors[prefix or "."] = str(exc)
            return
        for name in names:
            relative = f"{prefix}/{name}" if prefix else name
            if any(fnmatch.fnmatchcase(relative, p) or fnmatch.fnmatchcase(name, p)
                   for p in patterns):
                continue
            try:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=directory_fd)
                    try:
                        visit(child, relative)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode):
                    result.hashes[relative] = hash_file(name, dir_fd=directory_fd)
                else:
                    logger.debug("Skipped symlink or special file: %s", relative)
            except OSError as exc:
                result.errors[relative] = str(exc)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        visit(fd, "")
    finally:
        os.close(fd)
    return result
