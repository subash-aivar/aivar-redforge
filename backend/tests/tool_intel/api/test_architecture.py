"""Architecture/security-scan tests for the tool_intel API layer,
mirroring `tests/campaign_intel/api/test_architecture.py`'s
convention."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "tool_intel"
API_ROOT = ROOT / "api"

_ORM_IMPORT = re.compile(
    r"^\s*(from|import)\s+tool_intel\.infrastructure\.persistence\.(models|repositories)\b",
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
    from tool_intel.api.schemas import tool_schemas

    request_schema_names = [
        "ObserveToolRequest",
        "AddAliasRequest",
        "AddPlatformRequest",
        "AddCapabilityRequest",
        "AddEvidenceCitationRequest",
        "AddSourceAttributionRequest",
        "LifecycleTransitionRequest",
        "SupersedeToolRequest",
    ]
    for name in request_schema_names:
        schema_cls = getattr(tool_schemas, name)
        assert "tenant_id" not in schema_cls.model_fields, (
            f"{name} must not accept tenant_id as request-body authority"
        )


def test_explicit_observation_routes_use_the_correct_gate() -> None:
    routes_text = (API_ROOT / "v1" / "tools.py").read_text()
    tenant_obs = re.search(r"async def observe_tenant_tool\(.*?\n\) -> ", routes_text, re.S)
    global_obs = re.search(r"async def observe_global_tool\(.*?\n\) -> ", routes_text, re.S)
    assert tenant_obs is not None
    assert global_obs is not None
    assert "require_permission(" in tenant_obs.group(0)
    assert "require_platform_permission" not in tenant_obs.group(0)
    assert "require_platform_permission(" in global_obs.group(0)
    assert "require_permission(" not in global_obs.group(0)


def test_canonical_routes_have_no_static_permission_gate() -> None:
    """Every canonical `{tool_id}` route derives authorization
    dynamically from the loaded Tool's ownership scope
    (`_authorize_scope`) — none may depend on a static
    `require_permission(...)`/`require_platform_permission(...)` gate."""
    routes_text = (API_ROOT / "v1" / "tools.py").read_text()
    canonical_handlers = [
        "get_tool",
        "add_alias",
        "add_platform",
        "add_capability",
        "add_evidence_citation",
        "add_source_attribution",
        "deprecate_tool",
        "revoke_tool",
        "supersede_tool",
        "reactivate_tool",
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
            f"{name} must derive authorization from loaded Tool ownership scope"
        )


def test_public_route_count_matches_approved_canonical_contract() -> None:
    """14 total: 2 explicit observation routes + 2 unambiguous list
    routes + 10 canonical single `{tool_id}` routes (get, aliases,
    platforms, capabilities, evidence-citations, source-attributions,
    deprecate, revoke, supersede, reactivate)."""
    from redforge.app import create_app

    app = create_app()
    schema = app.openapi()
    tool_paths = [p for p in schema["paths"] if "/tool-intel" in p]
    assert len(tool_paths) == 14, sorted(tool_paths)


def test_no_delete_endpoint() -> None:
    routes_text = (API_ROOT / "v1" / "tools.py").read_text()
    assert ".delete(" not in routes_text, "no delete endpoint is permitted"


def test_no_relationship_endpoint() -> None:
    """Relationships belong to `intelligence_relationships` — this
    context exposes no relationship route."""
    routes_text = (API_ROOT / "v1" / "tools.py").read_text()
    assert "relationship" not in routes_text.lower()


def test_lifecycle_routes_are_all_present_and_distinct() -> None:
    routes_text = (API_ROOT / "v1" / "tools.py").read_text()
    for lifecycle_route in ("deprecate", "revoke", "supersede", "reactivate"):
        assert f'"/{{tool_id}}/{lifecycle_route}"' in routes_text
