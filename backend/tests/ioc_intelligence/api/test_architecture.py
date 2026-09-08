"""Architecture/security-scan tests for the ioc_intelligence API layer
(M51.2 Phase A4). Proves no forbidden pattern was introduced (mission
security-review requirement #9): no X-Roles header trust, no
request-body tenant_id authority, no organization permission gating a
global mutation, no direct repository/ORM access, no application
bypass."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "ioc_intelligence"
API_ROOT = ROOT / "api"

_ORM_IMPORT = re.compile(
    r"^\s*(from|import)\s+ioc_intelligence\.infrastructure\.persistence\.(models|repositories)\b",
    re.M,
)
_SQLALCHEMY_IMPORT = re.compile(r"^\s*(from|import)\s+sqlalchemy\b", re.M)
_X_ROLES = re.compile(r"x[-_]roles", re.I)


def _api_files() -> list[Path]:
    return list(API_ROOT.rglob("*.py"))


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
    from ioc_intelligence.api.schemas import ioc_schemas

    request_schema_names = [
        "ObserveIocRequest",
        "AddSourceAttributionRequest",
        "AddEvidenceCitationRequest",
        "TransitionLifecycleRequest",
        "TransitionEpistemicStateRequest",
        "RefuteIocRequest",
        "SourceAttributionRequest",
        "EvidenceCitationRequest",
    ]
    for name in request_schema_names:
        schema_cls = getattr(ioc_schemas, name)
        assert "tenant_id" not in schema_cls.model_fields, (
            f"{name} must not accept tenant_id as request-body authority"
        )


def test_explicit_observation_routes_use_the_correct_gate() -> None:
    routes_text = (API_ROOT / "v1" / "iocs.py").read_text()
    tenant_obs = re.search(r"async def observe_tenant_ioc\(.*?\n\) -> ", routes_text, re.S).group(0)
    global_obs = re.search(r"async def observe_global_ioc\(.*?\n\) -> ", routes_text, re.S).group(0)
    assert "require_permission(" in tenant_obs
    assert "require_platform_permission" not in tenant_obs
    assert "require_platform_permission(" in global_obs
    assert "require_permission(" not in global_obs


def test_canonical_ioc_id_routes_have_no_static_permission_gate() -> None:
    """The 10 canonical `{ioc_id}` routes derive authorization
    dynamically from the loaded IOC's ownership scope
    (`_authorize_ioc_scope`) — none of them may depend on a static
    `require_permission(...)`/`require_platform_permission(...)` gate,
    since that would require knowing the resource's scope in advance
    from something client-supplied (forbidden) rather than from the
    loaded record."""
    routes_text = (API_ROOT / "v1" / "iocs.py").read_text()
    canonical_handlers = [
        "get_ioc",
        "add_source",
        "add_evidence",
        "transition_lifecycle",
        "refresh_ioc",
        "supersede_ioc",
        "revoke_ioc",
        "transition_epistemic_state",
        "dispute_ioc",
        "refute_ioc",
    ]
    assert len(canonical_handlers) == 10
    for name in canonical_handlers:
        match = re.search(rf"async def {name}\(.*?\n\) -> ", routes_text, re.S)
        assert match is not None, f"canonical handler {name} not found"
        body = match.group(0)
        assert "require_permission(" not in body, f"{name} must not use a static tenant gate"
        assert "require_platform_permission(" not in body, (
            f"{name} must not use a static platform gate"
        )
        assert "_authorize_ioc_scope" in body or "OptionalTenantContextDep" in body, (
            f"{name} must derive authorization from loaded IOC ownership scope"
        )


def test_no_ambiguous_scope_selector_in_canonical_routes() -> None:
    """No `{ioc_id}` route may accept a client-supplied 'scope' query
    parameter, header, or body field to pick tenant vs. global —
    ownership is derived only from the loaded record."""
    routes_text = (API_ROOT / "v1" / "iocs.py").read_text()
    assert "scope: " not in routes_text
    assert 'Query(default="tenant")' not in routes_text
    assert "global_scope" not in routes_text


def test_public_route_count_matches_approved_canonical_contract() -> None:
    """15 total: 2 explicit observation routes + 2 unambiguous list
    routes (never duplicated) + 10 canonical single `{ioc_id}` routes
    (down from the prior 24, which duplicated every {ioc_id} operation
    into tenant/global siblings) + 1 platform-only maintenance route
    (`POST /iocs/maintenance/expire-lapsed`, M51.2 Slice 2 — closes the
    verified "no automated TTL/expiry enforcement" production gap by
    exposing a bounded, idempotent, platform-authority-gated sweep an
    external scheduler/operator can invoke; it mutates no {ioc_id}
    directly and adds no bulk/provider/correlation/enrichment surface)."""
    from redforge.app import create_app

    app = create_app()
    schema = app.openapi()
    ioc_paths = [p for p in schema["paths"] if "/iocs" in p]
    assert len(ioc_paths) == 15, sorted(ioc_paths)


def test_no_delete_endpoint() -> None:
    routes_text = (API_ROOT / "v1" / "iocs.py").read_text()
    assert ".delete(" not in routes_text, "no delete endpoint is permitted"


def test_no_bulk_or_provider_or_correlation_or_enrichment_endpoints() -> None:
    routes_text = (API_ROOT / "v1" / "iocs.py").read_text()
    for forbidden in ("bulk", "provider", "correlate", "correlation", "enrich"):
        assert forbidden not in routes_text.lower(), f"unexpected {forbidden!r} endpoint surface"
