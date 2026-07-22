from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "autonomous_intelligence"
BAD = re.compile(
    r"from (detection|campaign|playbook|vulnerability|engagement|incident|exposure|"
    r"automated_action|integration_hub)\."
)


def test_no_cross_context_domain_import_in_autonomous_intelligence() -> None:
    for p in ROOT.rglob("*.py"):
        if "infrastructure/acl" in str(p):
            continue
        text = p.read_text()
        if BAD.search(text):
            raise AssertionError(f"cross-context import in {p}")
