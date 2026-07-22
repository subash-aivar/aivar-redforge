from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "automated_action"


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "infrastructure" / "acl").is_dir()
    assert (ROOT / "infrastructure" / "workers").is_dir()


def test_no_cross_context_domain_imports() -> None:
    bad = re.compile(r"from (playbook|integration_hub|detection|incident|engagement|exposure)\.")
    for p in ROOT.rglob("*.py"):
        if "infrastructure/acl" in str(p):
            continue
        if bad.search(p.read_text()):
            raise AssertionError(p)
