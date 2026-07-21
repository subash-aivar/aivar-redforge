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
    assert heads == ["0113"]
