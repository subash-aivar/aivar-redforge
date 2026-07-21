from __future__ import annotations

import ast
from pathlib import Path

RI = Path(__file__).resolve().parents[2] / "src" / "exposure_reporting"

FORBIDDEN_OUTSIDE_ACL = (
    "exposure.domain",
    "remediation_impact.domain",
    "vulnerability.domain",
    "ai_posture.domain",
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
    assert (RI / "domain/aggregates/exposure_report.py").exists()
    assert (RI / "domain/aggregates/business_impact_mapping.py").exists()
    assert (RI / "domain/services/narrative_template_service.py").exists()
    assert (RI / "domain/ports/i_security_graph_write_port.py").exists()
    assert (RI / "api/v1/routes.py").exists()


def test_no_foreign_domain_outside_acl() -> None:
    for path in RI.rglob("*.py"):
        if "acl" in path.parts:
            continue
        for name in _imports(path):
            for forbidden in FORBIDDEN_OUTSIDE_ACL:
                assert not name.startswith(forbidden), f"{path} imports {name}"


def test_graph_port_is_write_only() -> None:
    text = (RI / "domain/ports/i_security_graph_write_port.py").read_text()
    assert "upsert_exposure_node" in text
    assert "upsert_exposure_edge" in text
    assert "async def get_" not in text
    assert "async def list_" not in text


def test_no_llm_dependency_in_narrative_service() -> None:
    text = (RI / "domain/services/narrative_template_service.py").read_text()
    assert "openai" not in text.lower()
    assert "llm" not in text.lower()
    assert "ADR-M32-005" in text or "template" in text.lower()
