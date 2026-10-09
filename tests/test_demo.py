import os
import subprocess
import sys
from pathlib import Path


def test_installed_cli_demo():
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root / "examples" / "demo.py")],
                            cwd=root, capture_output=True, text=True, encoding="utf-8",
                            env={**os.environ, "PYTHONUTF8": "1"})
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Unchanged: 2" in result.stdout
    assert "Modified: 1" in result.stdout
    assert "New: 1" in result.stdout
    assert "Deleted: 1" in result.stdout
    assert "Baseline authentication and SQLite integrity checks passed" in result.stdout
    assert "Demo passed" in result.stdout
