"""Command line interface. Exit codes: 0 clean, 1 changes, 2 errors."""

import argparse
import json
import logging
import os
import sqlite3
from pathlib import Path

from fim.baseline import compare, read_key, sign_baseline, verify_baseline
from fim.database import Database
from fim.reporter import report
from fim.scanner import scan_directory


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(description="SHA-256 file integrity monitor (POSIX)")
    subcommands = cli.add_subparsers(dest="command", required=True)
    for name in ("init", "scan", "status", "history", "verify-baseline"):
        command = subcommands.add_parser(name)
        command.add_argument("--db", type=Path, required=True, help="Baseline SQLite path outside monitored root")
        command.add_argument("--key", type=Path, required=True, help="External HMAC key (at least 32 random bytes)")
        command.add_argument("-v", "--verbose", action="store_true")
        if name in ("init", "scan"):
            command.add_argument("directory", type=Path)
        if name == "init":
            command.add_argument("--exclude", action="append", default=[], help="Relative path or basename glob; repeatable")
        if name == "history":
            command.add_argument("--limit", type=int, default=20)
    return cli


def validate_locations(root: Path, db: Path, key: Path) -> None:
    """Keep state and key outside the monitored directory and separated."""
    if not root.is_dir():
        raise ValueError("Monitored path must be an existing directory")
    if db.is_relative_to(root) or key.is_relative_to(root):
        raise ValueError("Database and key must be outside the monitored directory")
    if db.parent == key.parent or db == key:
        raise ValueError("Key must be stored in a different directory from the database")


def run(args: argparse.Namespace) -> int:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("This release requires a POSIX system (Linux/macOS)")
    db_path = args.db.resolve()
    key_path = args.key.resolve(strict=True)
    if db_path == key_path:
        raise ValueError("Database and key must be separate files")
    key = read_key(key_path)
    if args.command == "init":
        root = args.directory.resolve(strict=True)
        validate_locations(root, db_path, key_path)
        if db_path.exists():
            raise ValueError("Database already exists; choose a new --db to create a new baseline")
        result = scan_directory(root, args.exclude)
        if result.errors:
            raise ValueError("Baseline not created: " + json.dumps(result.errors, ensure_ascii=True))
        database = Database(db_path, create=True)
        try:
            database.save_baseline(str(root), args.exclude, result.hashes,
                                   sign_baseline(key, str(root), args.exclude, result.hashes))
        finally:
            database.close()
        print(f"Baseline created: {len(result.hashes)} files")
        return 0
    database = Database(db_path)
    try:
        root_name, excludes, hashes, signature = database.load_baseline()
        root = Path(root_name)
        # Verify signed metadata before trusting paths or exclusions.
        verify_baseline(key, root_name, excludes, hashes, signature)
        if db_path.parent == key_path.parent or key_path.is_relative_to(root) or db_path.is_relative_to(root):
            raise ValueError("Database/key locations violate separation requirements")
        if args.command == "verify-baseline":
            print("Baseline authentication and SQLite integrity checks passed")
        elif args.command == "scan":
            if args.directory.resolve(strict=True) != root:
                raise ValueError("Directory does not match this database's baseline")
            result = scan_directory(root, excludes)
            statuses = {} if result.errors else compare(hashes, result.hashes)
            scan_id = database.save_scan(statuses, result.errors)
            print(f"Scan #{scan_id}: {'incomplete' if result.errors else 'complete'}")
            report(statuses | {p: "error" for p in result.errors}, args.verbose)
            for path, error in result.errors.items():
                logging.error("Read failed: %s", json.dumps({path: error}, ensure_ascii=True))
            if result.errors:
                return 2
            return int(any(status != "unchanged" for status in statuses.values()))
        elif args.command == "history":
            if args.limit < 1:
                raise ValueError("--limit must be positive")
            rows = database.history(args.limit)
            if not rows:
                print("No scans recorded")
            for scan_id, timestamp, complete in rows:
                print(f"#{scan_id} {timestamp} {'complete' if complete else 'incomplete'}")
                if args.verbose:
                    report(database.events(scan_id), True)
        elif args.command == "status":
            rows = database.history(1)
            if not rows:
                print("Baseline authenticated; no scans recorded")
            else:
                scan_id, timestamp, complete = rows[0]
                print(f"Latest scan #{scan_id} {timestamp} {'complete' if complete else 'incomplete'}")
                report(database.events(scan_id), args.verbose)
    finally:
        database.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse arguments and turn expected failures into useful diagnostics."""
    args = parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s: %(message)s")
    try:
        return run(args)
    except (OSError, ValueError, sqlite3.Error, TypeError) as exc:
        logging.error("%s", json.dumps(str(exc), ensure_ascii=True))
        return 2
