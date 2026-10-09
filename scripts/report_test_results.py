"""Expose actionable pytest failures as GitHub Actions annotations."""

from pathlib import Path
import xml.etree.ElementTree as ET

results = Path("test-results.xml")
if results.is_file():
    for case in ET.parse(results).iter("testcase"):
        for kind in ("failure", "error"):
            failure = case.find(kind)
            if failure is None:
                continue
            text = f"{case.get('classname')}.{case.get('name')}: {(failure.text or '')[-3500:]}"
            escaped = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::error title=pytest failure::{escaped}")
