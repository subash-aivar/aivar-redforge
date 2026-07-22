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


def test_0086_to_0092_phase1() -> None:
    assert 'revision: str = "0086"' in _read("0086_analytics_schema_and_roles.py")
    assert 'down_revision: str = "0085"' in _read("0086_analytics_schema_and_roles.py")
    assert "CREATE SCHEMA IF NOT EXISTS analytics" in _read("0086_analytics_schema_and_roles.py")
    assert 'down_revision: str = "0086"' in _read("0087_analytics_vulnerability_events.py")
    assert 'down_revision: str = "0091"' in _read("0092_analytics_attck_reference_table.py")


def test_0093_to_0095_phase2() -> None:
    assert 'revision: str = "0093"' in _read("0093_analytics_queries_and_audit_log.py")
    assert 'down_revision: str = "0092"' in _read("0093_analytics_queries_and_audit_log.py")
    assert "CREATE SCHEMA IF NOT EXISTS reporting" in _read(
        "0094_reporting_templates_and_schedules.py"
    )
    assert "report_instances" in _read("0095_report_instances.py")


def test_0096_to_0098_phase3() -> None:
    assert "CREATE SCHEMA IF NOT EXISTS ml_pipeline" in _read("0096_ml_models.py")
    assert "ml_model_artifacts" in _read("0097_ml_model_artifacts.py")
    assert "predictive_risk_signals" in _read("0098_predictive_risk_signals.py")
    assert 'down_revision: str = "0097"' in _read("0098_predictive_risk_signals.py")


def test_0099_to_0101_phase4_phase5() -> None:
    assert 'revision: str = "0099"' in _read("0099_reporting_delivery_log.py")
    assert 'down_revision: str = "0098"' in _read("0099_reporting_delivery_log.py")
    assert "report_delivery_log" in _read("0099_reporting_delivery_log.py")
    assert "bi_export_rate_limit_log" in _read("0100_bi_export_rate_limit_log.py")
    assert 'down_revision: str = "0099"' in _read("0100_bi_export_rate_limit_log.py")
    assert "operational_metrics" in _read("0101_analytics_operational_metrics.py")
    assert 'down_revision: str = "0100"' in _read("0101_analytics_operational_metrics.py")


def test_single_head() -> None:
    """The chain has exactly one head — not literally "0149" forever, since
    later milestones (and this repository's own post-M36 hardening pass)
    legitimately extend it. Reuses the same ScriptDirectory-based lookup
    the app's own startup validators use
    (redforge/infrastructure/database/migration_head.py), so this can't go
    stale the way the hardcoded-literal version of this test did — it
    already broke twice independently (incident, playbook) before this
    third occurrence.
    """
    from redforge.infrastructure.database.migration_head import get_expected_migration_head

    # get_current_head() itself raises if there is more than one head, so
    # a successful call here already proves single-headedness.
    assert get_expected_migration_head()
