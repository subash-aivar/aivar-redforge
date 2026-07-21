from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "incident"


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "application" / "services").is_dir()
    assert (ROOT / "infrastructure" / "acl").is_dir()


def test_no_upstream_domain_imports() -> None:
    bad = re.compile(
        r"from (detection|evidence|engagement|exposure|analytics|campaign|execution|vulnerability)\."
    )
    for p in ROOT.rglob("*.py"):
        if "infrastructure/acl" in str(p):
            continue
        text = p.read_text()
        if bad.search(text):
            raise AssertionError(f"upstream import in {p}")
