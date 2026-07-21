from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "regulatory_notification"


def test_no_incident_domain_imports() -> None:
    bad = re.compile(r"from incident\.domain")
    for p in ROOT.rglob("*.py"):
        if bad.search(p.read_text()):
            raise AssertionError(p)
