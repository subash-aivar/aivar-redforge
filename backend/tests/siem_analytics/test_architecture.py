from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "siem_analytics"
INFRA_IMPORT = re.compile(r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic)\b", re.M)
SIEM_CONTEXT_IMPORT = re.compile(
    r"from (siem_ingestion|siem_normalization|siem_storage|siem_detection|"
    r"siem_correlation|siem_investigation|siem_alerting|siem_search)\."
)


def test_layout() -> None:
    assert (ROOT / "domain" / "value_objects").is_dir()
    assert (ROOT / "application").is_dir()
    assert (ROOT / "infrastructure").is_dir()
    assert (ROOT / "api").is_dir()


def test_owns_no_aggregate() -> None:
    assert not (ROOT / "domain" / "aggregates").exists()


def test_domain_layer_has_no_infrastructure_imports() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the domain layer")


def test_domain_layer_does_not_import_sibling_siem_contexts() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if SIEM_CONTEXT_IMPORT.search(text):
            raise AssertionError(f"{path} imports a sibling siem_* context from the domain layer")


def test_application_layer_has_no_infrastructure_imports() -> None:
    infra_import = re.compile(
        r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka|"
        r"elasticsearch|opensearchpy)\b",
        re.M,
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
    """M44F's own explicit scope guard: this milestone implements
    analytics aggregation only — no dashboards, executive reporting,
    or risk scoring may appear anywhere in this bounded context's
    application-layer source."""
    banned = re.compile(
        r"\b(Dashboard|ExecutiveReport|ExecutiveScor(e|ing)|RiskScor(e|ing)|RiskEngine)\b"
    )
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references out-of-scope vocabulary: {match.group()}")


def test_analytics_engine_is_read_only_no_writer_port_exists() -> None:
    """M44F's special review: analytics remains read-only — this
    context defines no outbound writer/receiver port at all, because
    there is nothing for it to persist or hand off."""
    port_files = [p.name for p in (ROOT / "application" / "ports").glob("*.py")]
    banned_names = {"i_analytics_writer.py", "i_analytics_receiver.py", "i_event_receiver.py"}
    assert not (banned_names & set(port_files)), port_files


def test_analytics_application_service_holds_no_growing_state() -> None:
    """Same discipline as M44A-M44E: the service must carry only its
    injected collaborators between calls, never a dict/list attribute
    that would grow unboundedly."""
    text = (
        ROOT / "application" / "services" / "analytics_application_service.py"
    ).read_text()
    init_body = text.split("def __init__", 1)[1].split("def ", 1)[0]
    banned_state = re.compile(r"self\._\w+\s*[:=]\s*(\{\}|\[\]|dict\(\)|list\(\))")
    match = banned_state.search(init_body)
    assert match is None, f"service initializes a growable collection attribute: {match}"
