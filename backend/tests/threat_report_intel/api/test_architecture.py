"""Architecture/security-scan tests for the threat_report_intel API
layer, mirroring `tests/infrastructure_intel/api/test_architecture.py`'s
convention."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "threat_report_intel"
API_ROOT = ROOT / "api"

_ORM_IMPORT = re.compile(
    r"^\s*(from|import)\s+threat_report_intel\.infrastructure\.persistence\."
    r"(models|repositories)\b",
    re.M,
)
_SQLALCHEMY_IMPORT = re.compile(r"^\s*(from|import)\s+sqlalchemy\b", re.M)
_X_ROLES = re.compile(r"x[-_]roles", re.I)


def _api_files() -> list[Path]:
    return list(API_ROOT.rglob("*.py"))


def _routes_text() -> str:
    return (API_ROOT / "v1" / "threat_reports.py").read_text()


def test_api_layer_exists() -> None:
    assert API_ROOT.is_dir()


def test_no_orm_or_repository_imports_in_api_layer() -> None:
    for path in _api_files():
        text = path.read_text()
        if _ORM_IMPORT.search(text):
            raise AssertionError(f"{path} imports ORM models/repositories directly")


def test_no_sqlalchemy_imports_in_routes_or_schemas() -> None:
    for subdir in ("v1", "schemas"):
        for path in (API_ROOT / subdir).rglob("*.py"):
            text = path.read_text()
            if _SQLALCHEMY_IMPORT.search(text):
                raise AssertionError(f"{path} imports sqlalchemy directly")


def test_no_x_roles_header_trust_anywhere_in_api_layer() -> None:
    for path in _api_files():
        text = path.read_text()
        if _X_ROLES.search(text):
            raise AssertionError(f"{path} references an X-Roles-style header — forbidden")


def test_routes_never_accept_tenant_id_from_request_body() -> None:
    from threat_report_intel.api.schemas import threat_report_schemas

    request_schema_names = [
        "ObserveThreatReportRequest",
        "AddReferenceRequest",
        "AddEvidenceCitationRequest",
        "AddSourceAttributionRequest",
        "LifecycleTransitionRequest",
        "SupersedeThreatReportRequest",
    ]
    for name in request_schema_names:
        schema_cls = getattr(threat_report_schemas, name)
        assert "tenant_id" not in schema_cls.model_fields, (
            f"{name} must not accept tenant_id as request-body authority"
        )


def test_the_observe_request_requires_both_distinct_summaries() -> None:
    from threat_report_intel.api.schemas.threat_report_schemas import (
        ObserveThreatReportRequest,
    )

    fields = ObserveThreatReportRequest.model_fields
    assert "executive_summary" in fields
    assert "technical_summary" in fields
    assert fields["executive_summary"].is_required()
    assert fields["technical_summary"].is_required()


def test_explicit_observation_routes_use_the_correct_gate() -> None:
    routes_text = _routes_text()
    tenant_obs = re.search(
        r"async def observe_tenant_threat_report\(.*?\n\) -> ", routes_text, re.S
    )
    global_obs = re.search(
        r"async def observe_global_threat_report\(.*?\n\) -> ", routes_text, re.S
    )
    assert tenant_obs is not None
    assert global_obs is not None
    assert "require_permission(" in tenant_obs.group(0)
    assert "require_platform_permission" not in tenant_obs.group(0)
    assert "require_platform_permission(" in global_obs.group(0)
    assert "require_permission(" not in global_obs.group(0)


def test_canonical_routes_have_no_static_permission_gate() -> None:
    """Every canonical `{threat_report_id}` route derives authorization
    dynamically from the loaded record's ownership scope
    (`_authorize_scope`) — none may depend on a static
    `require_permission(...)`/`require_platform_permission(...)` gate."""
    routes_text = _routes_text()
    canonical_handlers = [
        "get_threat_report",
        "add_reference",
        "add_evidence_citation",
        "add_source_attribution",
        "deprecate_threat_report",
        "revoke_threat_report",
        "supersede_threat_report",
        "reactivate_threat_report",
    ]
    for name in canonical_handlers:
        match = re.search(rf"async def {name}\(.*?\n\) -> ", routes_text, re.S)
        assert match is not None, f"canonical handler {name} not found"
        body = match.group(0)
        assert "require_permission(" not in body, f"{name} must not use a static tenant gate"
        assert "require_platform_permission(" not in body, (
            f"{name} must not use a static platform gate"
        )
        assert "_authorize_scope" in body or "OptionalTenantContextDep" in body, (
            f"{name} must derive authorization from loaded record ownership scope"
        )


def test_public_route_count_matches_approved_canonical_contract() -> None:
    """12 total: 2 explicit observation routes + 2 unambiguous list
    routes + 8 canonical single `{threat_report_id}` routes (get,
    references, evidence-citations, source-attributions, deprecate,
    revoke, supersede, reactivate)."""
    from redforge.app import create_app

    app = create_app()
    schema = app.openapi()
    paths = [p for p in schema["paths"] if "/threat-report-intel" in p]
    assert len(paths) == 12, sorted(paths)


def test_no_delete_endpoint() -> None:
    assert ".delete(" not in _routes_text(), "no delete endpoint is permitted"


def test_no_relationship_endpoint() -> None:
    """Relationships belong to `intelligence_relationships` — this
    context exposes no relationship route. The router docstring is
    allowed (and required) to EXPLAIN that, so only route paths and
    decorators are scanned here."""
    routes_text = _routes_text()
    body = routes_text.split('"""', 2)[2] if routes_text.count('"""') >= 2 else routes_text
    route_decorators = re.findall(r'@threat_report_router\.\w+\(\s*"([^"]*)"', body)
    for path in route_decorators:
        assert "relationship" not in path.lower(), path
    assert "RelationshipCommand" not in body
    assert "add_relationship" not in body


def test_the_router_documents_relationship_support_via_intelligence_relationships() -> None:
    """The API surface's silence about relationships is deliberate and
    must be explained where a reader looking for the missing endpoint
    would look — including that the capability exists today, just not
    here."""
    from threat_report_intel.api.v1 import threat_reports

    doc = (threat_reports.__doc__ or "").lower()
    assert "intelligence_relationships" in doc
    assert "relationshiptype" in doc
    assert "threat_report" in doc
    assert "threat_report_to_" in doc
    assert "duplicate a certified capability" in doc


def test_lifecycle_routes_are_all_present_and_distinct() -> None:
    routes_text = _routes_text()
    for lifecycle_route in ("deprecate", "revoke", "supersede", "reactivate"):
        assert f'"/{{threat_report_id}}/{lifecycle_route}"' in routes_text
