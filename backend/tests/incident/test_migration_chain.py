from __future__ import annotations

from pathlib import Path

VERSIONS = (
    Path(__file__).resolve().parents[2] / "src/redforge/infrastructure/database/migrations/versions"
)


def _read(name: str) -> str:
    return (VERSIONS / name).read_text()


def test_0102_to_0113_chain() -> None:
    assert 'revision: str = "0102"' in _read("0102_analytics_incident_events.py")
    assert 'down_revision: str = "0101"' in _read("0102_analytics_incident_events.py")
    assert "incident_events" in _read("0102_analytics_incident_events.py")
    assert 'down_revision: str = "0102"' in _read("0103_incident_core_tables.py")
    assert 'down_revision: str = "0104"' in _read("0105_regulatory_notification_schema.py")
    assert 'down_revision: str = "0107"' in _read("0108_eradication_verification.py")
    assert 'down_revision: str = "0110"' in _read("0111_lessons_learned_tables.py")
    assert 'down_revision: str = "0112"' in _read("0113_incident_operational_metrics.py")
    assert "REVOKE UPDATE, DELETE" in _read("0110_communication_log.py")


def test_0113_extended_exactly_once() -> None:
    """0113 was the incident context's own last migration in M34.

    This does not assert 0113 is the *global* migration head — later
    milestones legitimately extend the chain past it (0114 onward). It only
    guards against a second, conflicting migration being added with
    down_revision="0113", which would fork the chain.
    """
    children = [
        path.name
        for path in VERSIONS.glob("*.py")
        if 'down_revision: str = "0113"' in path.read_text()
    ]
    assert children == ["0114_playbooks_core.py"]
