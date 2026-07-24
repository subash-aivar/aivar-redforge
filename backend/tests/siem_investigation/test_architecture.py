from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "siem_investigation"
INFRA_IMPORT = re.compile(r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic)\b", re.M)
DOWNSTREAM_CONTEXT_IMPORT = re.compile(r"from (siem_search|siem_analytics)\.")


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
    """M44D's own explicit scope guard: this milestone never calculates
    risk, scores executively, or implements search/analytics."""
    banned = re.compile(
        r"\b(RiskScor(e|ing)|ExecutiveScor(e|ing)|ExecutiveDashboard|"
        r"SearchIndex|SearchQuery|AnalyticsAggregat(e|ion))\b"
    )
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} references out-of-scope vocabulary: {match.group()}")


def test_investigation_application_service_reuses_timeline_not_reimplements_it() -> None:
    """The application layer must call `InvestigationTimeline.create`/
    `.add_entry` (M43A) rather than constructing/mutating a timeline
    through any other path — verifies M44D's "reuse, don't reimplement
    ordering logic, don't bypass aggregate methods" requirement
    structurally, not just by convention."""
    text = (
        ROOT / "application" / "services" / "investigation_application_service.py"
    ).read_text()
    assert "InvestigationTimeline.create(" in text
    assert "timeline.add_entry(" in text
    # No direct field assignment or ordering logic bypassing the aggregate.
    assert "timeline.entries =" not in text
    assert "timeline.entries.insert(" not in text
    assert "timeline.entries.append(" not in text
    assert "bisect" not in text


def test_investigation_application_service_holds_no_growing_state() -> None:
    """Same discipline as M44B/M44C: the service must carry only its
    injected collaborators between calls, never a dict/list attribute
    that would grow unboundedly."""
    text = (
        ROOT / "application" / "services" / "investigation_application_service.py"
    ).read_text()
    init_body = text.split("def __init__", 1)[1].split("def ", 1)[0]
    banned_state = re.compile(r"self\._\w+\s*[:=]\s*(\{\}|\[\]|dict\(\)|list\(\))")
    match = banned_state.search(init_body)
    assert match is None, f"service initializes a growable collection attribute: {match}"
