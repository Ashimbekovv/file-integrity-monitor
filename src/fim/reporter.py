"""Readable terminal reports; quote paths to escape terminal control characters."""

import json
from collections import Counter


def report(statuses: dict[str, str], verbose: bool = False) -> None:
    counts = Counter(statuses.values())
    for status in ("modified", "new", "deleted", "unchanged", "error"):
        print(f"{status.capitalize()}: {counts[status]}")
    for path, status in sorted(statuses.items()):
        if verbose or status != "unchanged":
            print(f"  {status.upper():9} {json.dumps(path, ensure_ascii=False)}")
