import sqlite3
import pytest
from fim.database import Database


def test_persistence_and_history(tmp_path):
    path = tmp_path / "test.db"
    db = Database(path, create=True)
    db.save_baseline("/root", [], {"a": "hash"}, "signature")
    scan_id = db.save_scan({"a": "unchanged"}, {})
    db.close()
    reopened = Database(path)
    try:
        assert reopened.load_baseline() == ("/root", [], {"a": "hash"}, "signature")
        assert reopened.history()[0][0] == scan_id
        assert reopened.events(scan_id) == {"a": "unchanged"}
        failed = reopened.save_scan({}, {"a": "denied"})
        assert reopened.history()[0][2] == 0
        assert reopened.events(failed) == {"a": "error"}
    finally:
        reopened.close()


def test_corrupt_database(tmp_path):
    path = tmp_path / "bad.db"
    path.write_bytes(b"not a SQLite database")
    with pytest.raises(sqlite3.DatabaseError):
        Database(path)


def test_missing_database(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        Database(tmp_path / "absent.db")


def test_no_overwrite(tmp_path):
    path = tmp_path / "existing"
    path.write_text("user data")
    with pytest.raises(FileExistsError):
        Database(path, create=True)
    assert path.read_text() == "user data"
