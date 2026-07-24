from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "siem_detection"
INFRA_IMPORT = re.compile(r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic)\b", re.M)
DOWNSTREAM_CONTEXT_IMPORT = re.compile(
    r"from (siem_correlation|siem_investigation|siem_alerting|siem_search|siem_analytics)\."
)


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "application").is_dir()
    assert (ROOT / "infrastructure").is_dir()
    assert (ROOT / "api").is_dir()


def test_domain_layer_has_no_infrastructure_imports() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the domain layer")


def test_does_not_depend_on_downstream_siem_contexts() -> None:
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if DOWNSTREAM_CONTEXT_IMPORT.search(text):
            raise AssertionError(f"{path} imports a downstream siem_* context")


def test_application_layer_has_no_infrastructure_imports() -> None:
    infra_import = re.compile(
        r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka)\b", re.M
    )
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if infra_import.search(text):
            raise AssertionError(f"{path} imports infrastructure from the application layer")


def test_infrastructure_and_api_layers_remain_empty_stubs() -> None:
    for layer in ("infrastructure", "api"):
        files = sorted(p.name for p in (ROOT / layer).rglob("*.py"))
        assert files == ["__init__.py"], f"{layer}/ is no longer an empty stub: {files}"


def test_no_out_of_scope_engine_vocabulary() -> None:
    """M44A's own explicit scope guard: this milestone implements the
    Detection Engine only — no Sigma/YARA parser, no correlation, no
    alert generation, no investigation, no risk scoring may appear
    anywhere in this bounded context's source."""
    banned = re.compile(
        r"\b(SigmaParser|SigmaCompiler|YaraRule|CorrelationSession|"
        r"AlertRaised|RaiseAlert|OpenInvestigation|RiskScor(e|ing))\b"
    )
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references out-of-scope vocabulary: {match.group()}")


def test_detection_match_never_imports_alerting() -> None:
    """DetectionMatch must never import siem_alerting — turning matches
    into alerts is that context's job, not this one's."""
    text = (ROOT / "application" / "dtos" / "detection_match.py").read_text()
    assert "import siem_alerting" not in text
    assert "from siem_alerting" not in text
