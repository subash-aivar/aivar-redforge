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


def test_0080_extended_exactly_once() -> None:
    """0080 was the ai_posture context's own last migration in M31.

    This does not assert 0080 is the *global* migration head — later
    milestones legitimately extend the chain past it (0081 onward). It only
    guards against a second, conflicting migration being added with
    down_revision="0080", which would fork the chain.

    (The original version of this test scanned for the substring
    'revision: str = "0080"' across every migration file — which also
    incidentally matches inside any later file's own
    'down_revision: str = "0080"' line, since "down_revision" ends with
    "revision". That false positive is what broke this test once 0081
    legitimately declared 0080 as its down_revision; see
    tests/incident/test_migration_chain.py::test_0113_extended_exactly_once
    for the same fork-guard pattern this now follows.)
    """
    children = [
        path.name
        for path in VERSIONS.glob("*.py")
        if 'down_revision: str = "0080"' in path.read_text()
    ]
    assert children == ["0081_exposure_phase1_foundation.py"]
