"""Architecture constraints: no LLM, no writes to M27/M32 domains, no analytics.domain outside ACL."""

from __future__ import annotations

import ast
from pathlib import Path

ML = Path(__file__).resolve().parents[2] / "src" / "ml_pipeline"

FORBIDDEN_OUTSIDE_ACL = (
    "analytics.domain",
    "vulnerability.domain",
    "exposure.domain",
    "exposure_reporting.domain",
    "remediation_impact.domain",
    "ai_posture.domain",
)

LLM_MARKERS = (
    "openai",
    "anthropic",
    "langchain",
    "litellm",
    "transformers",
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
    assert (ML / "domain/aggregates/ml_model.py").exists()
    assert (ML / "domain/aggregates/predictive_risk_signal.py").exists()
    assert (ML / "domain/services/ml_model_training_service.py").exists()
    assert (ML / "domain/services/ml_inference_service.py").exists()
    assert (ML / "domain/services/model_governance_service.py").exists()
    assert (ML / "domain/services/drift_detection_service.py").exists()
    assert (ML / "infrastructure/workers/ml_workers.py").exists()
    assert (ML / "api/v1/routes.py").exists()
    assert (ML / "py.typed").exists()


def test_no_foreign_domain_outside_acl() -> None:
    for path in ML.rglob("*.py"):
        if "acl" in path.parts:
            continue
        for name in _imports(path):
            for forbidden in FORBIDDEN_OUTSIDE_ACL:
                assert not name.startswith(forbidden), f"{path} imports {name}"


def test_no_llm_dependency() -> None:
    for path in ML.rglob("*.py"):
        text = path.read_text().lower()
        for marker in LLM_MARKERS:
            assert marker not in text, f"{path} references LLM marker {marker}"
        for name in _imports(path):
            for marker in LLM_MARKERS:
                assert marker not in name.lower(), f"{path} imports {name}"


def test_router_export() -> None:
    from ml_pipeline.api.v1 import router

    assert router.prefix == "/ml-pipeline"


def test_graph_adapter_only_predictive_risk() -> None:
    text = (ML / "infrastructure/acl/security_graph_write_adapter.py").read_text()
    assert "predictive_risk" in text
    assert "upsert_predictive_risk_node" in text
