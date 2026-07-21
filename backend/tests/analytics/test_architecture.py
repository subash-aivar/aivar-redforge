from __future__ import annotations

import ast
from pathlib import Path

ANALYTICS = Path(__file__).resolve().parents[2] / "src" / "analytics"

FORBIDDEN_OUTSIDE_ACL = (
    "vulnerability.domain",
    "detection.domain",
    "exposure.domain",
    "campaign.domain",
    "ai_posture.domain",
    "exposure_reporting.domain",
    "ml_pipeline.domain",
    "reporting.domain",
)


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text())
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def test_layout() -> None:
    assert (ANALYTICS / "domain/aggregates/analytics_dataset.py").exists()
    assert (ANALYTICS / "domain/aggregates/security_kpi.py").exists()
    assert (ANALYTICS / "domain/aggregates/anomaly_detection_baseline.py").exists()
    assert (ANALYTICS / "domain/aggregates/analytics_query.py").exists()
    assert (ANALYTICS / "domain/services/kpi_computation_service.py").exists()
    assert (ANALYTICS / "infrastructure/workers/analytics_workers.py").exists()
    assert (ANALYTICS / "api/v1/routes.py").exists()


def test_no_foreign_domain_outside_acl() -> None:
    for path in ANALYTICS.rglob("*.py"):
        if "acl" in path.parts:
            continue
        for name in _imports(path):
            for forbidden in FORBIDDEN_OUTSIDE_ACL:
                assert not name.startswith(forbidden), f"{path} imports {name}"


def test_repository_interfaces_require_tenant_id() -> None:
    text = (ANALYTICS / "domain/repositories/i_analytics_repositories.py").read_text()
    assert "tenant_id" in text
    assert "IAnalyticsDataSetRepository" in text
    assert "ISecurityKPIRepository" in text
