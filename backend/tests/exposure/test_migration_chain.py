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


def _read(name: str) -> str:
    return (VERSIONS / name).read_text()


def test_0081_phase1_chain() -> None:
    text = _read("0081_exposure_phase1_foundation.py")
    assert 'revision: str = "0081"' in text
    assert 'down_revision: str = "0080"' in text


def test_0082_phase3_chain() -> None:
    text = _read("0082_exposure_phase3_threat_actor_match_cache.py")
    assert 'revision: str = "0082"' in text
    assert 'down_revision: str = "0081"' in text


def test_0083_phase4_chain() -> None:
    text = _read("0083_remediation_impact_phase4_plans.py")
    assert 'revision: str = "0083"' in text
    assert 'down_revision: str = "0082"' in text


def test_0084_phase5_reports() -> None:
    text = _read("0084_exposure_reporting_phase5_reports.py")
    assert 'revision: str = "0084"' in text
    assert 'down_revision: str = "0083"' in text
    assert "CREATE SCHEMA IF NOT EXISTS exposure_reporting" in text
    assert "exposure_reports" in text
    assert "exposure_kpi_projections" in text
    assert "exposure_trend_projections" in text


def test_0085_phase5_business_impact() -> None:
    text = _read("0085_exposure_reporting_phase5_business_impact.py")
    assert 'revision: str = "0085"' in text
    assert 'down_revision: str = "0084"' in text
    assert "business_impact_mappings" in text
    assert "uq_bim_tenant_asset" in text


def test_single_head_0113() -> None:
    """The chain has exactly one head — not literally "0113" forever, since
    later milestones (and this repository's own post-M36 hardening pass)
    legitimately extend it. Reuses the same ScriptDirectory-based lookup
    the app's own startup validators use
    (redforge/infrastructure/database/migration_head.py), so this can't go
    stale the way the hardcoded-literal version of this test did — see
    tests/analytics/test_migration_chain.py::test_single_head for the
    same fix applied there first.
    """
    from redforge.infrastructure.database.migration_head import get_expected_migration_head

    # get_current_head() itself raises if there is more than one head, so
    # a successful call here already proves single-headedness.
    assert get_expected_migration_head()
