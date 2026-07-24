from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "siem_correlation"
INFRA_IMPORT = re.compile(r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic)\b", re.M)
DOWNSTREAM_CONTEXT_IMPORT = re.compile(
    r"from (siem_investigation|siem_alerting|siem_search|siem_analytics)\."
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


def test_correlation_session_has_no_unbounded_accumulate_bypass() -> None:
    """Every code path that appends to `correlated_event_ids` must sit
    behind the OPEN-status + window-elapsed guard in `accumulate()` —
    guards against a future edit accidentally adding a second,
    unguarded append path (the exact regression class M37 §6 warns
    against)."""
    text = (ROOT / "domain" / "aggregates" / "correlation_session.py").read_text()
    assert text.count("correlated_event_ids.append(") == 1


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
    """M44B's own explicit scope guard: this milestone implements the
    Correlation Engine only — no Alert creation, no Investigation, no
    Incident, no Risk Engine, no executive scoring, no Sigma/YARA may
    appear anywhere in this bounded context's source."""
    banned = re.compile(
        r"\b(RaiseAlert|AlertRaised|OpenInvestigation|IncidentCreated|"
        r"RiskScor(e|ing)|ExecutiveScor(e|ing)|SigmaParser|SigmaCompiler|YaraRule)\b"
    )
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references out-of-scope vocabulary: {match.group()}")


def test_correlation_application_service_holds_no_growing_state() -> None:
    """The application service must carry only its injected
    collaborators (registry/provider/writer) and scalar configuration
    (max size, window) between calls — no dict/list attribute that
    would grow unboundedly across sessions over the service's lifetime.
    Every mutation must go through `ICorrelationSessionWriter`
    immediately, never accumulate in the service itself."""
    text = (
        ROOT / "application" / "services" / "correlation_application_service.py"
    ).read_text()
    init_body = text.split("def __init__", 1)[1].split("def ", 1)[0]
    banned_state = re.compile(r"self\._\w+\s*[:=]\s*(\{\}|\[\]|dict\(\)|list\(\))")
    match = banned_state.search(init_body)
    assert match is None, f"service initializes a growable collection attribute: {match}"
