# File Integrity Monitor

## Project Overview

File Integrity Monitor (FIM) is an educational defensive security tool for Python
3.11+ on Windows, Linux and macOS. It compares SHA-256 file hashes against an authenticated
baseline and records scan history in SQLite. It detects changes; it does not
prevent attacks or prove that the initial files are safe.

The project uses small modules and the Python standard library at runtime.
`__init__.py` is the Python package marker (rather than `init.py`), and
`__main__.py` supports `python -m fim`.

## Features

- Recursive scanning of a directory explicitly selected by the user.
- Classification as modified, new, deleted, or unchanged.
- Immutable baseline, authenticated with HMAC-SHA-256 and an external key.
- Persisted scan summaries and per-file events, including incomplete scan errors.
- Repeatable exclusion patterns, Unicode names, spaces, and verbose reports.
- Symlinks and special files are skipped; descriptor-based traversal prevents
  symlink substitution on POSIX, and pinned native directory handles prevent it
  on Windows. Windows junctions and all other reparse points are also skipped.
- Detection of observable file changes while reading; incomplete scans never
  report inaccessible files as deleted.
- SQLite integrity checks and an explicit baseline verification command.

## Technologies

Python 3.11+, `hashlib`, `hmac`, `pathlib`, `os`, `sqlite3`, `argparse`,
`logging`, pytest, Git, and GitHub. No runtime third-party dependencies, servers,
Docker, web frontend, or API credentials are required.

## Installation

**Windows users:** see the [Windows quick start](WINDOWS.md) for PowerShell
commands in Russian. No WSL, Ubuntu, administrator access or PowerShell activation
script is needed. Once installed, run `.\.venv\Scripts\python.exe examples\demo.py`
for a disposable demonstration that does not touch personal files.

From the repository root on Linux/macOS:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
python -m pip install -r requirements-dev.txt
fim --help
python examples/demo.py
```

## Usage

Use a directory you own and trust. Keep the SQLite database outside that directory
and the key in a **different directory from the database**, also outside the
monitored directory. The CLI enforces these location rules. Create a random
32-byte key once and retain it securely; do not replace it on subsequent scans.

The following example uses separate directories under your home directory. The
key generator refuses to overwrite an existing key and creates it with mode 0600.
The commands never edit monitored files.

```sh
mkdir -p "$HOME/fim-demo" "$HOME/.local/state/fim" "$HOME/.config/fim-keys"
chmod 700 "$HOME/.config/fim-keys"
python - <<'PY'
import os
import secrets
from pathlib import Path
key = Path.home() / '.config/fim-keys/demo.key'
fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'wb') as stream:
    stream.write(secrets.token_bytes(32))
PY

fim init "$HOME/fim-demo" \
  --db "$HOME/.local/state/fim/demo.db" \
  --key "$HOME/.config/fim-keys/demo.key" \
  --exclude '*.log' --exclude '.git'

fim scan "$HOME/fim-demo" \
  --db "$HOME/.local/state/fim/demo.db" \
  --key "$HOME/.config/fim-keys/demo.key" --verbose

fim status --db "$HOME/.local/state/fim/demo.db" --key "$HOME/.config/fim-keys/demo.key"
fim history --db "$HOME/.local/state/fim/demo.db" --key "$HOME/.config/fim-keys/demo.key" --limit 10 --verbose
fim verify-baseline --db "$HOME/.local/state/fim/demo.db" --key "$HOME/.config/fim-keys/demo.key"
```

All commands require `--db` and `--key`. `init` and `scan` additionally require
the directory. The directory is resolved to an absolute path; `scan` must match
the signed baseline root. `status` shows the latest **recorded** scan rather than
performing a new scan. `history` uses UTC timestamps and defaults to 20 scans.
Every command authenticates the baseline before trusting it (except `init`,
which creates it).

Exclusions use case-sensitive shell-style glob patterns against either a relative
POSIX path (`nested/file.txt`) or a basename (`*.log`). A matching directory is
pruned along with its children. Quote patterns to prevent shell expansion.
Patterns are signed and retained in the database; changing them requires creating
a new baseline in a new database. With Python `fnmatch`, `*` can match `/`.

Exit codes: **0** successful/clean, **1** changes detected by `scan`, **2** errors,
invalid arguments, authentication failure, or incomplete scans. `status` and
`history` return 0 when successfully displaying records, even if those records
contain changes. An incomplete scan records errors only; its comparison is
intentionally omitted. Fix access or instability, then scan again.

Initialization refuses an existing database and never silently updates a trusted
baseline. After reviewing legitimate changes, explicitly initialize a new database
file. Keep older databases if their history is useful. A failed database write may
leave an incomplete file; inspect it and choose a new database path for a retry.

## Example Output

Illustrative output after one file changes, one is added, and one is removed:

```text
Scan #2: complete
Modified: 1
New: 1
Deleted: 1
Unchanged: 1
Error: 0
  MODIFIED  "config.txt"
  DELETED   "old.txt"
  NEW       "Новый файл.txt"
```

`--verbose` also lists unchanged files and enables diagnostic logging. Paths are
quoted to escape terminal control characters. No monitored file contents or key
values are printed.

## Testing

```sh
python -m pytest -q
```

Tests use temporary directories, not personal files. Coverage includes streaming
SHA-256, concurrent file mutation, missing files/directories, deterministic
permission failure simulation, symlink exclusion, recursive exclusions, Unicode,
empty baselines, all four change classifications, database corruption, repeat
initialization, persistence across reopening, wrong roots, key separation, and
signed-baseline tampering. Permission denial is simulated so the test also works
when run as root. GitHub Actions runs the suite and installed CLI demo on Windows,
Linux and macOS with Python 3.11 and 3.13. Native Windows tests check junctions,
handle-based rename protection, binary reading and symlink substitution. Those
tests are skipped on other operating systems; symlink tests may additionally skip
on Windows machines without link-creation privileges.

## Security Considerations

- SHA-256 authenticates file contents only when compared to a trusted baseline.
  Create that baseline from files you have independently reviewed.
- HMAC-SHA-256 authenticates the canonical root, exclusions and complete file/hash
  mapping. The key is never stored in SQLite. Use cryptographically random bytes,
  restrictive filesystem permissions, secure backups, and a separate key directory.
  On Windows, `chmod(0600)` does not establish a private NTFS access-control list;
  use your private Windows user profile and configure ACLs for production keys.
  A length check cannot determine whether a key actually has sufficient entropy.
- `verify-baseline` checks SQLite structure and the baseline HMAC. Ordinary JSON
  is used only for deterministic encoding, not as a security boundary.
- Scan history is **not authenticated**. An attacker who can write the database
  can alter or delete history. HMAC protects baseline content, not availability.
- An attacker with access to both the database and key can forge a baseline.
  Physical directory separation alone does not protect against the same user,
  administrator, malware running as that user, or a compromised host.
- Replacing the entire database with an older valid signed copy is a replay/rollback
  attack that this release cannot detect. Protect the baseline's location and
  maintain an independently trusted record if rollback detection is required.
- Symlinks are skipped, including internal ones. Hard links are regular files;
  the tool cannot establish whether an inode has additional links elsewhere.
  On Windows, all reparse points are skipped, including OneDrive placeholders.
  Use an ordinary local directory for complete coverage. Windows opens directory
  ancestors without delete sharing for the duration of traversal. Existing handles
  with incompatible sharing cause a read error rather than less safe scanning.
- No user file is modified or deleted by scanning. Only the explicitly supplied
  database is written. No automatic system-wide scanning occurs.
- Never commit keys, databases, `.env` files, virtual environments, or personal
  monitoring data. `.gitignore` is a convenience, not a substitute for review.

## Limitations

- Baseline roots are absolute, platform-specific paths. Create a new baseline
  when moving monitored files between machines or operating systems.
- No filesystem snapshot or locking: a scan is not an atomic view of a live tree.
  Metadata checks detect many file changes during reading but cannot guarantee
  detection of adversarial concurrent mutations. Quiesce important directories
  before creating baselines. Files may change immediately after being read.
- File ownership, permissions, timestamps, and extended attributes are not baseline
  properties. Content changes alone determine modified/unchanged status.
- Renames appear as one deletion and one addition. Excluded/symlink/special-file
  contents are outside coverage. Replacing a tracked regular file with a symlink
  appears as deletion of the tracked regular file.
- Missing root directories and database authentication failures stop before a scan
  record can be created. Read errors inside the root create an incomplete record.
- No concurrent-writer coordination, background scheduling, notifications, key
  rotation, remote storage, or authenticated audit history. Run one CLI operation
  per database at a time. History grows until you archive the database.

## Future Improvements

- Authenticate audit history and anchor baseline revisions externally for rollback detection.
- Optional file metadata policies and broader filesystem compatibility testing.
- Snapshot-aware scanning, scheduled execution, and local notifications.
- History export and retention, after documenting their security properties.

## License

MIT; see [LICENSE](LICENSE).

## GitHub Publication

For this existing repository, after configuring your own local GitHub access:

```sh
git remote -v                    # Verify the intended destination
git status                      # Review local changes
git push -u origin main
```

The configured destination is `https://github.com/Ashimbekovv/file-integrity-monitor.git`.
Do not create another repository with the same name. A successful local commit
is not proof that publication succeeded. Never share authentication tokens in chat.
