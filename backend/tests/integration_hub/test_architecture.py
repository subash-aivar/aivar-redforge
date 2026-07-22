from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "integration_hub"
BANNED = re.compile(r"(api_key|secret|password|token|private_key|certificate)\s*[:=]", re.I)


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "application" / "ports").is_dir()


def test_no_plaintext_secret_fields_in_aggregate_source() -> None:
    text = (ROOT / "domain" / "aggregates" / "connector_registration.py").read_text()
    # credential_ref / vault_key allowed; plaintext field assignments banned
    assert "credential_vault_key" not in text or "CredentialRef" in text
    for line in text.splitlines():
        if "banned" in line or "secret_keys" in line or "intersection" in line:
            continue
        if BANNED.search(line) and "CredentialRef" not in line:
            raise AssertionError(line)


def test_no_upstream_domain_imports() -> None:
    bad = re.compile(r"from (playbook|automated_action|detection|incident|engagement|exposure)\.")
    for p in ROOT.rglob("*.py"):
        if bad.search(p.read_text()):
            raise AssertionError(p)
