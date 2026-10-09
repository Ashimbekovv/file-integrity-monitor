"""Run a disposable demonstration with the installed package, on any platform."""

import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="fim-demo-") as temporary:
        base = Path(temporary)
        root, state, keys = (base / name for name in ("files", "state", "keys"))
        for folder in (root, state, keys):
            folder.mkdir()
        key = keys / "demo.key"
        key.write_bytes(secrets.token_bytes(32))
        key.chmod(0o600)
        database = state / "demo.db"
        sample = root / "example.txt"
        sample.write_text("Hello\n", encoding="utf-8")
        (root / "unchanged.txt").write_text("Keep this file\n", encoding="utf-8")

        def run(command: str, expected: int = 0) -> None:
            args = [sys.executable, "-m", "fim", command,
                    "--db", str(database), "--key", str(key)]
            if command in ("init", "scan"):
                args.extend([str(root), "--verbose"])
            result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8",
                                    env={**os.environ, "PYTHONUTF8": "1"})
            print(result.stdout, end="")
            if result.stderr:
                print(result.stderr, end="", file=sys.stderr)
            if result.returncode != expected:
                raise RuntimeError(f"{command}: expected exit {expected}, got {result.returncode}")

        print("1. Create baseline")
        run("init")
        print("\n2. Check unchanged files")
        run("scan")
        print("\n3. Modify one file and add another")
        sample.write_text("Changed\n", encoding="utf-8")
        (root / "new file.txt").write_text("New\n", encoding="utf-8")
        run("scan", 1)
        print("\n4. Delete the original file")
        sample.unlink()
        run("scan", 1)
        print("\n5. Show history")
        run("history")
        print("\n6. Verify baseline")
        run("verify-baseline")
    print("\nDemo passed. Temporary files, database and key have been removed.")


if __name__ == "__main__":
    main()
