from __future__ import annotations

import ast
from pathlib import Path

EXPOSURE = Path(__file__).resolve().parents[2] / "src" / "exposure"
SRC = Path(__file__).resolve().parents[2] / "src"

FORBIDDEN_OUTSIDE_ACL = (
    "vulnerability.domain",
    "detection.domain",
    "ai_posture.domain",
    "redforge.domain",
    "remediation_impact.domain",
    "exposure_reporting.domain",
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


def test_module_layout() -> None:
    assert (EXPOSURE / "domain" / "aggregates" / "exposure_record.py").exists()
    assert (EXPOSURE / "application" / "services" / "score_pipeline_service.py").exists()
    assert (EXPOSURE / "infrastructure" / "container.py").exists()
    assert (EXPOSURE / "api" / "v1" / "routes.py").exists()
    assert (EXPOSURE / "infrastructure" / "projections" / "threat_actor_match_cache.py").exists()
    assert (EXPOSURE / "application" / "services" / "exposure_scope_service.py").exists()


def test_no_foreign_domain_imports_outside_acl() -> None:
    for path in EXPOSURE.rglob("*.py"):
        if "acl" in path.parts:
            continue
        for name in _imports(path):
            for forbidden in FORBIDDEN_OUTSIDE_ACL:
                assert not name.startswith(forbidden), f"{path} imports {name}"


def test_rbac_canonical_roles() -> None:
    enums = (EXPOSURE / "domain/value_objects/enums.py").read_text()
    assert 'VIEWER = "exposure:viewer"' in enums
    assert 'ANALYST = "exposure:analyst"' in enums
    assert 'SIMULATION_READER = "exposure:simulation_reader"' in enums
    assert 'ADMIN = "exposure:admin"' in enums


def test_detection_gap_not_signal_domain() -> None:
    enums = (EXPOSURE / "domain/value_objects/enums.py").read_text()
    assert "VulnerabilityManagement" in enums
    assert "CloudSecurity" in enums
    assert 'DETECTION = "Detection"' not in enums


def test_phase5_package_present() -> None:
    assert (SRC / "exposure_reporting").is_dir()
    assert (SRC / "exposure_reporting" / "domain" / "aggregates" / "exposure_report.py").exists()
    assert (
        SRC / "exposure_reporting" / "domain" / "aggregates" / "business_impact_mapping.py"
    ).exists()


def test_phase4_package_present() -> None:
    assert (SRC / "remediation_impact").is_dir()
    assert (SRC / "campaign" / "domain" / "ports" / "i_exposure_scope_query_port.py").exists()


def test_identity_documented_in_aggregate() -> None:
    text = (EXPOSURE / "domain/aggregates/exposure_record.py").read_text()
    assert "ADR-M32-001" in text or "signal-scoped" in text
