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


def test_single_head_0113() -> None:
    revisions: dict[str, str] = {}
    down_revisions: set[str] = set()
    for path in VERSIONS.glob("*.py"):
        text = path.read_text()
        rev = down = None
        for line in text.splitlines():
            if line.startswith("revision:"):
                rev = line.split("=")[1].strip().strip('"')
            if line.startswith("down_revision:"):
                down = line.split("=")[1].strip().strip('"')
        if rev:
            revisions[rev] = path.name
            if down and down != "None":
                down_revisions.add(down)
    heads = [r for r in revisions if r not in down_revisions]
    assert heads == ["0113"]
