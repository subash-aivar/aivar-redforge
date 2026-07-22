from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "playbook"


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "application" / "services").is_dir()
    assert (ROOT / "infrastructure" / "persistence").is_dir()


def test_no_upstream_domain_imports() -> None:
    bad = re.compile(
        r"from (detection|evidence|engagement|exposure|analytics|campaign|execution|"
        r"vulnerability|incident|regulatory_notification|lessons_learned|automated_action|"
        r"integration_hub)\."
    )
    for p in ROOT.rglob("*.py"):
        if "infrastructure/acl" in str(p):
            continue
        text = p.read_text()
        if bad.search(text):
            raise AssertionError(f"upstream import in {p}")


def test_no_secret_field_names_in_domain() -> None:
    banned = re.compile(r"\b(api_key|password|private_key)\b")
    for p in (ROOT / "domain").rglob("*.py"):
        text = p.read_text()
        if banned.search(text) and "secret_keys" not in text:
            raise AssertionError(f"secret field name in {p}")
