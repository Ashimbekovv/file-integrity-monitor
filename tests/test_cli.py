import sqlite3
import pytest
from fim.cli import main


def command(workspace, name, *extra):
    root, db, key = workspace
    args = [name, "--db", str(db), "--key", str(key)]
    if name in ("init", "scan"):
        args.append(str(root))
    return main(args + list(extra))


def test_complete_workflow(workspace, capsys):
    root, db, key = workspace
    (root / "same").write_text("same")
    (root / "modified").write_text("before")
    (root / "deleted").write_text("gone")
    assert command(workspace, "init") == 0
    assert command(workspace, "scan") == 0
    (root / "modified").write_text("after")
    (root / "deleted").unlink()
    (root / "Новый файл").write_text("new")
    assert command(workspace, "scan", "-v") == 1
    output = capsys.readouterr().out
    assert "Modified: 1" in output and "New: 1" in output and "Deleted: 1" in output
    assert "Unchanged: 1" in output and "Новый файл" in output
    for name in ("status", "history", "verify-baseline"):
        assert command(workspace, name, "-v") == 0
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT count(*) FROM scans").fetchone()[0] == 2


def test_empty_and_repeat_init(workspace):
    assert command(workspace, "init") == 0
    assert command(workspace, "scan") == 0
    assert command(workspace, "init") == 2


def test_missing_baseline(workspace):
    assert command(workspace, "scan") == 2


@pytest.mark.parametrize("sql", ["UPDATE baseline SET digest='tampered'",
                                  "UPDATE metadata SET root='/tmp'",
                                  "UPDATE metadata SET excludes='[\"*\"]'"])
def test_tampering(workspace, sql):
    root, db, key = workspace
    (root / "file").write_text("content")
    assert command(workspace, "init") == 0
    with sqlite3.connect(db) as connection:
        connection.execute(sql)
    assert command(workspace, "verify-baseline") == 2
    assert command(workspace, "scan") == 2


def test_corrupt_database(workspace):
    workspace[1].write_bytes(b"broken")
    assert command(workspace, "status") == 2


def test_incomplete_scan_has_no_false_deletions(workspace, monkeypatch):
    root, db, key = workspace
    (root / "file").write_text("data")
    assert command(workspace, "init") == 0
    def denied(*args, **kwargs):
        raise PermissionError("denied")
    monkeypatch.setattr("fim.scanner.hash_file", denied)
    assert command(workspace, "scan") == 2
    with sqlite3.connect(db) as connection:
        assert connection.execute("SELECT status FROM events").fetchall() == [("error",)]


def test_key_separation(workspace):
    root, db, key = workspace
    near = db.parent / "key"
    near.write_bytes(key.read_bytes())
    assert main(["init", str(root), "--db", str(db), "--key", str(near)]) == 2
    inside = root / "key"
    inside.write_bytes(key.read_bytes())
    assert main(["init", str(root), "--db", str(db), "--key", str(inside)]) == 2
    assert not db.exists()


def test_wrong_root(workspace, tmp_path):
    assert command(workspace, "init") == 0
    other = tmp_path / "other"
    other.mkdir()
    assert main(["scan", str(other), "--db", str(workspace[1]), "--key", str(workspace[2])]) == 2


def test_exclusions_saved(workspace):
    (workspace[0] / "ignored.log").write_text("original")
    assert command(workspace, "init", "--exclude", "*.log") == 0
    (workspace[0] / "ignored.log").write_text("changed")
    assert command(workspace, "scan") == 0
