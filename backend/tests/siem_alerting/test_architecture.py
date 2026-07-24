from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "siem_alerting"
INFRA_IMPORT = re.compile(r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic)\b", re.M)
DOWNSTREAM_CONTEXT_IMPORT = re.compile(r"from (siem_investigation|siem_search|siem_analytics)\.")
INCIDENT_IMPORT = re.compile(r"from incident\.")


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


def test_alert_domain_layer_never_imports_incident() -> None:
    """M37 §8/§11: siem_alerting publishes, incident subscribes — the
    dependency runs one way only. The domain layer must never reach
    into incident's own aggregate/domain code."""
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if INCIDENT_IMPORT.search(text):
            raise AssertionError(f"{path} imports incident from siem_alerting's domain layer")


def test_application_layer_never_imports_incident_or_investigation() -> None:
    """M44C's own explicit scope guard: this milestone never opens an
    Investigation or an Incident — only Alert creation/suppression/
    dedup, all via the frozen Alert aggregate."""
    banned = re.compile(r"from (incident|siem_investigation)\.")
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if banned.search(text):
            raise AssertionError(f"{path} imports incident/investigation from the application layer")


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
    """No risk scoring, no executive dashboards, no investigation/
    incident creation may appear anywhere in this bounded context's
    application-layer source."""
    banned = re.compile(
        r"\b(RiskScor(e|ing)|ExecutiveScor(e|ing)|ExecutiveDashboard|"
        r"OpenInvestigation|CreateIncident|IncidentCreated)\b"
    )
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references out-of-scope vocabulary: {match.group()}")


def test_alert_application_service_reuses_lifecycle_not_reimplements_it() -> None:
    """The application layer must call `Alert.raise_alert`/`.suppress`/
    `.deduplicate` (M43A) rather than constructing/mutating an `Alert`
    through any other path — verifies M44C's "reuse, don't duplicate
    lifecycle logic" requirement structurally, not just by convention."""
    text = (
        ROOT / "application" / "services" / "alert_application_service.py"
    ).read_text()
    assert "Alert.raise_alert(" in text
    assert "alert.suppress(" in text
    assert "alert.deduplicate(" in text
    # No direct field assignment bypassing the aggregate's own methods.
    assert "alert.status =" not in text
    assert "alert._status" not in text


def test_alert_application_service_holds_no_growing_state() -> None:
    """Same discipline as M44B's correlation service: the alert service
    must carry only its injected collaborators between calls, never a
    dict/list attribute that would grow unboundedly."""
    text = (
        ROOT / "application" / "services" / "alert_application_service.py"
    ).read_text()
    init_body = text.split("def __init__", 1)[1].split("def ", 1)[0]
    banned_state = re.compile(r"self\._\w+\s*[:=]\s*(\{\}|\[\]|dict\(\)|list\(\))")
    match = banned_state.search(init_body)
    assert match is None, f"service initializes a growable collection attribute: {match}"
