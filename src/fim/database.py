"""SQLite persistence; one database holds one immutable baseline."""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path


class Database:
    """Manage baseline and atomic scan history transactions."""

    def __init__(self, path: Path, *, create: bool = False):
        if create:
            # Exclusive creation prevents accidental overwrite of any existing file.
            with path.open("xb"):
                pass
        elif not path.is_file():
            raise ValueError("Baseline database not found; run 'fim init' first")
        self.connection = sqlite3.connect(path)
        try:
            if create:
                self.connection.executescript("""
                    CREATE TABLE metadata (id INTEGER PRIMARY KEY CHECK(id=1),
                        root TEXT NOT NULL, excludes TEXT NOT NULL, signature TEXT NOT NULL);
                    CREATE TABLE baseline (path TEXT PRIMARY KEY, digest TEXT NOT NULL);
                    CREATE TABLE scans (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL,
                        complete INTEGER NOT NULL);
                    CREATE TABLE events (scan_id INTEGER NOT NULL REFERENCES scans(id),
                        path TEXT NOT NULL, status TEXT NOT NULL, detail TEXT,
                        PRIMARY KEY(scan_id, path));
                    PRAGMA user_version=1;
                """)
            if self.connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise ValueError("Database integrity check failed")
            if self.connection.execute("PRAGMA user_version").fetchone() != (1,):
                raise ValueError("Unsupported database schema")
            self.connection.execute("PRAGMA foreign_keys=ON")
        except Exception:
            self.connection.close()
            raise

    def close(self) -> None:
        self.connection.close()

    def save_baseline(self, root: str, excludes: list[str], hashes: dict[str, str],
                      signature: str) -> None:
        """Store baseline once; replacing it requires a new database."""
        with self.connection:
            self.connection.execute("INSERT INTO metadata VALUES (1, ?, ?, ?)",
                                    (root, json.dumps(excludes), signature))
            self.connection.executemany("INSERT INTO baseline VALUES (?, ?)", hashes.items())

    def load_baseline(self) -> tuple[str, list[str], dict[str, str], str]:
        row = self.connection.execute("SELECT root, excludes, signature FROM metadata WHERE id=1").fetchone()
        if row is None:
            raise ValueError("Database contains no baseline; create a new baseline database")
        root, raw_excludes, signature = row
        excludes = json.loads(raw_excludes)
        if not isinstance(excludes, list) or not all(isinstance(p, str) for p in excludes):
            raise ValueError("Invalid baseline exclusions")
        hashes = dict(self.connection.execute("SELECT path, digest FROM baseline"))
        return root, excludes, hashes, signature

    def save_scan(self, statuses: dict[str, str], errors: dict[str, str]) -> int:
        """Record complete comparisons or incomplete scans with errors only."""
        with self.connection:
            cursor = self.connection.execute("INSERT INTO scans(timestamp, complete) VALUES (?, ?)",
                (datetime.now(timezone.utc).isoformat(), int(not errors)))
            scan_id = cursor.lastrowid
            self.connection.executemany("INSERT INTO events VALUES (?, ?, ?, ?)",
                [(scan_id, p, s, None) for p, s in statuses.items()] +
                [(scan_id, p, "error", detail) for p, detail in errors.items()])
        return int(scan_id)

    def history(self, limit: int = 20) -> list[tuple]:
        return self.connection.execute("SELECT id, timestamp, complete FROM scans ORDER BY id DESC LIMIT ?",
                                       (limit,)).fetchall()

    def events(self, scan_id: int) -> dict[str, str]:
        return dict(self.connection.execute("SELECT path, status FROM events WHERE scan_id=? ORDER BY path",
                                            (scan_id,)))
