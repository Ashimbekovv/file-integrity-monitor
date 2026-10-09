import pytest
from fim.scanner import scan_directory


def test_empty(tmp_path):
    result = scan_directory(tmp_path)
    assert result.hashes == {} and result.errors == {}


def test_unicode_recursive_exclusions(tmp_path):
    (tmp_path / "Русский файл.txt").write_text("пример")
    folder = tmp_path / "nested"
    folder.mkdir()
    (folder / "keep").write_text("yes")
    (folder / "skip.log").write_text("no")
    result = scan_directory(tmp_path, ["*.log"])
    assert set(result.hashes) == {"Русский файл.txt", "nested/keep"}
    assert set(scan_directory(tmp_path, ["nested"]).hashes) == {"Русский файл.txt"}


def test_no_external_symlinks(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("secret")
    (root / "external").symlink_to(outside, target_is_directory=True)
    (root / "file-link").symlink_to(outside / "secret")
    assert scan_directory(root).hashes == {}


def test_unreadable_file(tmp_path, monkeypatch):
    (tmp_path / "file").write_text("data")
    def denied(*args, **kwargs):
        raise PermissionError("Access denied")
    monkeypatch.setattr("fim.scanner.hash_file", denied)
    result = scan_directory(tmp_path)
    assert "file" in result.errors and not result.hashes


def test_missing_directory(tmp_path):
    with pytest.raises(FileNotFoundError):
        scan_directory(tmp_path / "absent")
