"""Architecture regression guards for frozen M31."""

from __future__ import annotations

import ast
from pathlib import Path

AI_POSTURE = Path(__file__).resolve().parents[2] / "src" / "ai_posture"
SUPPLY = Path(__file__).resolve().parents[2] / "src" / "ai_supply_chain"
AGENT = Path(__file__).resolve().parents[2] / "src" / "ai_agent_governance"

FORBIDDEN_IMPORT_PREFIXES = (
    "redforge.domain",
    "inventory.domain",
    "assets.domain",
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


def test_module_layout_exists() -> None:
    assert (AI_POSTURE / "__init__.py").exists()
    assert (SUPPLY / "domain" / "aggregates").exists()
    assert (AGENT / "domain" / "aggregates").exists()


def test_no_m22_domain_imports_outside_acl() -> None:
    for root in (AI_POSTURE, SUPPLY, AGENT):
        for path in root.rglob("*.py"):
            if "acl" in path.parts:
                continue
            for name in _imports(path):
                for forbidden in FORBIDDEN_IMPORT_PREFIXES:
                    assert not name.startswith(forbidden), f"{path} imports {name}"


def test_threat_profile_is_separate_aggregate_module() -> None:
    asset_src = (AI_POSTURE / "domain/aggregates/ai_system_asset.py").read_text()
    assert "class AIThreatProfile" not in asset_src
    assert "AIThreatProfileRef" in asset_src


def test_agent_governance_does_not_import_ai_posture_domain_or_application() -> None:
    for path in AGENT.rglob("*.py"):
        for name in _imports(path):
            assert not name.startswith("ai_posture.domain"), path
            assert not name.startswith("ai_posture.application"), path


def test_rbac_canonical_prefix() -> None:
    enums = (AI_POSTURE / "domain/value_objects/enums.py").read_text()
    assert 'ENGINEER = "ai_posture:engineer"' in enums
    assert "mlsecops:engineer" not in enums


def test_phase5_compliance_and_projections_exist() -> None:
    assert (AI_POSTURE / "domain/aggregates/ai_compliance_mapping.py").exists()
    assert (AI_POSTURE / "application/projections/projection_service.py").exists()
    assert (AI_POSTURE / "domain/ports/i_compliance_query_port.py").exists()
    assert (AI_POSTURE / "domain/ports/i_security_graph_write_port.py").exists()


def test_no_fourth_bounded_context_package() -> None:
    src = Path(__file__).resolve().parents[2] / "src"
    forbidden = {"ai_spm_reports", "ai_security_graph", "m31_read_models"}
    present = {p.name for p in src.iterdir() if p.is_dir()}
    assert not (present & forbidden)
