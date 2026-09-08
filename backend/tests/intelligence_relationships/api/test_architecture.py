"""Architecture/security-scan tests for the intelligence_relationships
API layer (M51.4 Phase C1), mirroring `tests/attack_pattern_intel/api/
test_architecture.py`'s convention."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "intelligence_relationships"
API_ROOT = ROOT / "api"

_ORM_IMPORT = re.compile(
    r"^\s*(from|import)\s+intelligence_relationships\.infrastructure\.persistence\."
    r"(models|repositories)\b",
    re.M,
)
_SQLALCHEMY_IMPORT = re.compile(r"^\s*(from|import)\s+sqlalchemy\b", re.M)
_X_ROLES = re.compile(r"x[-_]roles", re.I)

CANONICAL_HANDLERS = [
    "get_relationship",
    "add_evidence_citation",
    "add_source_attribution",
    "transition_epistemic_state",
    "deprecate_relationship",
    "revoke_relationship",
    "supersede_relationship",
    "reactivate_relationship",
]


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
    from intelligence_relationships.api.schemas import relationship_schemas

    request_schema_names = [
        "ObserveRelationshipRequest",
        "AddEvidenceCitationRequest",
        "AddSourceAttributionRequest",
        "TransitionEpistemicStateRequest",
        "LifecycleTransitionRequest",
        "SupersedeRelationshipRequest",
    ]
    for name in request_schema_names:
        schema_cls = getattr(relationship_schemas, name)
        assert "tenant_id" not in schema_cls.model_fields, (
            f"{name} must not accept tenant_id as request-body authority"
        )


def test_explicit_observation_routes_use_the_correct_gate() -> None:
    routes_text = (API_ROOT / "v1" / "relationships.py").read_text()
    tenant_obs = re.search(
        r"async def observe_tenant_relationship\(.*?\n\) -> ", routes_text, re.S
    ).group(0)
    global_obs = re.search(
        r"async def observe_global_relationship\(.*?\n\) -> ", routes_text, re.S
    ).group(0)
    assert "require_permission(" in tenant_obs
    assert "require_platform_permission" not in tenant_obs
    assert "require_platform_permission(" in global_obs
    assert "require_permission(" not in global_obs


def test_canonical_routes_have_no_static_permission_gate() -> None:
    """Every canonical `{relationship_id}` route derives authorization
    dynamically from the loaded relationship's ownership scope
    (`_authorize_scope`) — none may depend on a static
    `require_permission(...)`/`require_platform_permission(...)` gate."""
    routes_text = (API_ROOT / "v1" / "relationships.py").read_text()
    for name in CANONICAL_HANDLERS:
        match = re.search(rf"async def {name}\(.*?\n\) -> ", routes_text, re.S)
        assert match is not None, f"canonical handler {name} not found"
        body = match.group(0)
        assert "require_permission(" not in body, f"{name} must not use a static tenant gate"
        assert "require_platform_permission(" not in body, (
            f"{name} must not use a static platform gate"
        )
        assert "_authorize_scope" in body or "OptionalTenantContextDep" in body, (
            f"{name} must derive authorization from loaded relationship ownership scope"
        )


def test_public_route_count_matches_approved_canonical_contract() -> None:
    """12 total: 2 explicit observation routes + 2 unambiguous list
    routes + 8 canonical single `{relationship_id}` routes (get,
    evidence-citations, source-attributions, epistemic-state,
    deprecate, revoke, supersede, reactivate)."""
    from redforge.app import create_app

    app = create_app()
    schema = app.openapi()
    paths = [p for p in schema["paths"] if p.startswith("/api/v1/relationships")]
    assert len(paths) == 12, sorted(paths)


def test_no_delete_endpoint() -> None:
    routes_text = (API_ROOT / "v1" / "relationships.py").read_text()
    assert ".delete(" not in routes_text, "no delete endpoint is permitted"


def test_relationship_permissions_are_registered_in_both_rbac_enums() -> None:
    from redforge.domain.identity.value_objects import Permission
    from redforge.domain.platform_identity.value_objects import PlatformPermission

    assert Permission.RELATIONSHIP_READ.value == "intelligence_relationships:read"
    assert Permission.RELATIONSHIP_OBSERVE.value == "intelligence_relationships:observe"
    assert Permission.RELATIONSHIP_MANAGE.value == "intelligence_relationships:manage"
    assert (
        PlatformPermission.PLATFORM_RELATIONSHIP_READ.value
        == "platform:intelligence_relationships:read"
    )
    assert (
        PlatformPermission.PLATFORM_RELATIONSHIP_MANAGE.value
        == "platform:intelligence_relationships:manage"
    )


def test_relationship_permissions_track_the_attack_pattern_role_grants() -> None:
    """The three tenant permissions were added to exactly the roles that
    already hold the equivalent ATTACK_PATTERN permission."""
    from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, Permission

    for role, permissions in ROLE_PERMISSIONS.items():
        assert (Permission.RELATIONSHIP_READ in permissions) is (
            Permission.ATTACK_PATTERN_READ in permissions
        ), role
        assert (Permission.RELATIONSHIP_OBSERVE in permissions) is (
            Permission.ATTACK_PATTERN_OBSERVE in permissions
        ), role
        assert (Permission.RELATIONSHIP_MANAGE in permissions) is (
            Permission.ATTACK_PATTERN_MANAGE in permissions
        ), role


def test_platform_relationship_permissions_track_attack_pattern_grants() -> None:
    from redforge.domain.platform_identity.value_objects import (
        PLATFORM_ROLE_PERMISSIONS,
        PlatformPermission,
    )

    for role, permissions in PLATFORM_ROLE_PERMISSIONS.items():
        assert (PlatformPermission.PLATFORM_RELATIONSHIP_READ in permissions) is (
            PlatformPermission.PLATFORM_ATTACK_PATTERN_READ in permissions
        ), role
        assert (PlatformPermission.PLATFORM_RELATIONSHIP_MANAGE in permissions) is (
            PlatformPermission.PLATFORM_ATTACK_PATTERN_MANAGE in permissions
        ), role
