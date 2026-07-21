"""Alembic migration chain validation for M31 Phase 1–5."""

from __future__ import annotations

from pathlib import Path

VERSIONS = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "redforge"
    / "infrastructure"
    / "database"
    / "migrations"
    / "versions"
)


def test_0076_phase1_chain() -> None:
    source = (VERSIONS / "0076_ai_posture_phase1_foundation.py").read_text()
    assert 'revision: str = "0076"' in source
    assert 'down_revision: str = "0075"' in source


def test_0077_phase2_chain() -> None:
    source = (VERSIONS / "0077_ai_posture_phase2_threat_risk.py").read_text()
    assert 'revision: str = "0077"' in source
    assert 'down_revision: str = "0076"' in source


def test_0078_phase3_chain() -> None:
    source = (VERSIONS / "0078_ai_supply_chain_phase3.py").read_text()
    assert 'revision: str = "0078"' in source
    assert 'down_revision: str = "0077"' in source


def test_0079_phase4_chain() -> None:
    source = (VERSIONS / "0079_ai_agent_governance_phase4.py").read_text()
    assert 'revision: str = "0079"' in source
    assert 'down_revision: str = "0078"' in source


def test_0080_phase5_chain() -> None:
    source = (VERSIONS / "0080_ai_posture_phase5_compliance_read_models.py").read_text()
    assert 'revision: str = "0080"' in source
    assert 'down_revision: str = "0079"' in source
    assert "ai_compliance_mappings" in source
    assert "ai_posture_read_models" in source
    assert "ai_security_graph_nodes" in source


def test_single_head_0080() -> None:
    heads = []
    for path in VERSIONS.glob("*.py"):
        text = path.read_text()
        if 'revision: str = "0080"' in text:
            heads.append(path.name)
    assert heads == ["0080_ai_posture_phase5_compliance_read_models.py"]
