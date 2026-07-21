from pathlib import Path

VERSIONS = (
    Path(__file__).resolve().parents[2] / "src/redforge/infrastructure/database/migrations/versions"
)


def test_0078_and_0079_chain() -> None:
    s78 = (VERSIONS / "0078_ai_supply_chain_phase3.py").read_text()
    s79 = (VERSIONS / "0079_ai_agent_governance_phase4.py").read_text()
    assert 'revision: str = "0078"' in s78
    assert 'down_revision: str = "0077"' in s78
    assert "provenance_chain_entries" in s78
    assert "reject_mutation" in s78
    assert 'revision: str = "0079"' in s79
    assert 'down_revision: str = "0078"' in s79
