from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "posture_forecasting"


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "py.typed").is_file()


def test_no_upstream_domain_imports() -> None:
    bad = re.compile(r"from (detection|campaign|playbook|autonomous_intelligence|threat_hunt)\.")
    for p in ROOT.rglob("*.py"):
        if "infrastructure/acl" in str(p):
            continue
        if bad.search(p.read_text()):
            raise AssertionError(p)
