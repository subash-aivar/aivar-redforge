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


def test_single_head_0101() -> None:
    revisions: dict[str, str] = {}
    down_revisions: set[str] = set()
    for path in VERSIONS.glob("*.py"):
        text = path.read_text()
        rev = None
        down = None
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
    assert heads == ["0101"]
