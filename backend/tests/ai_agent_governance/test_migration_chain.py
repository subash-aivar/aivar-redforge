from pathlib import Path

VERSIONS = (
    Path(__file__).resolve().parents[2] / "src/redforge/infrastructure/database/migrations/versions"
)


def test_0079_head_chain() -> None:
    source = (VERSIONS / "0079_ai_agent_governance_phase4.py").read_text()
    assert 'revision: str = "0079"' in source
    assert 'down_revision: str = "0078"' in source
