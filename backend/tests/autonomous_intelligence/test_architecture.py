from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "autonomous_intelligence"


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "application" / "services").is_dir()
    assert (ROOT / "infrastructure" / "acl").is_dir()
    assert (ROOT / "py.typed").is_file()
    assert (ROOT / "docs" / "eu_ai_act_conformity_template.md").is_file()
