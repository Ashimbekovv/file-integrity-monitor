"""Canonical baseline authentication and change classification."""

import hashlib
import hmac
import json
from pathlib import Path


class IntegrityError(ValueError):
    """The baseline cannot be trusted."""


def read_key(path: Path) -> bytes:
    """Read an externally managed key; never create or store it in the database."""
    key = path.read_bytes()
    if len(key) < 32:
        raise ValueError("Key must contain at least 32 bytes; use cryptographically random bytes")
    return key


def sign_baseline(key: bytes, root: str, excludes: list[str], hashes: dict[str, str]) -> str:
    """Authenticate root, exclusions and file hashes in a deterministic format."""
    payload = json.dumps({"version": 1, "root": root, "excludes": excludes, "hashes": hashes},
                         sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode()
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def verify_baseline(key: bytes, root: str, excludes: list[str], hashes: dict[str, str],
                    signature: str) -> None:
    """Reject a modified baseline or incorrect key before using its hashes."""
    if not hmac.compare_digest(sign_baseline(key, root, excludes, hashes), signature):
        raise IntegrityError("Baseline authentication failed: wrong key or modified database")


def compare(baseline: dict[str, str], current: dict[str, str]) -> dict[str, str]:
    """Return a status for every baseline or current relative path."""
    return {path: ("new" if path not in baseline else "deleted" if path not in current
                   else "unchanged" if baseline[path] == current[path] else "modified")
            for path in sorted(baseline.keys() | current.keys())}
