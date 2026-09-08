"""Architecture/security-scan tests for the attack_pattern_intel API
layer (M51.3 Phase B1), mirroring `tests/ioc_intelligence/api/
test_architecture.py`'s convention."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "attack_pattern_intel"
API_ROOT = ROOT / "api"

_ORM_IMPORT = re.compile(
    r"^\s*(from|import)\s+attack_pattern_intel\.infrastructure\.persistence\.(models|repositories)\b",
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
    from attack_pattern_intel.api.schemas import attack_pattern_schemas

    request_schema_names = [
        "ObserveAttackPatternRequest",
        "AddDetectionGuidanceRequest",
        "AddMitigationReferenceRequest",
        "AddProcedureExampleRequest",
        "AddRelationshipRequest",
        "LifecycleTransitionRequest",
        "SupersedeAttackPatternRequest",
    ]
    for name in request_schema_names:
        schema_cls = getattr(attack_pattern_schemas, name)
        assert "tenant_id" not in schema_cls.model_fields, (
            f"{name} must not accept tenant_id as request-body authority"
        )


def test_explicit_observation_routes_use_the_correct_gate() -> None:
    routes_text = (API_ROOT / "v1" / "attack_patterns.py").read_text()
    tenant_obs = re.search(
        r"async def observe_tenant_attack_pattern\(.*?\n\) -> ", routes_text, re.S
    ).group(0)
    global_obs = re.search(
        r"async def observe_global_attack_pattern\(.*?\n\) -> ", routes_text, re.S
    ).group(0)
    assert "require_permission(" in tenant_obs
    assert "require_platform_permission" not in tenant_obs
    assert "require_platform_permission(" in global_obs
    assert "require_permission(" not in global_obs


def test_canonical_routes_have_no_static_permission_gate() -> None:
    """Every canonical `{attack_pattern_id}` route derives authorization
    dynamically from the loaded AttackPattern's ownership scope
    (`_authorize_scope`) — none may depend on a static
    `require_permission(...)`/`require_platform_permission(...)` gate."""
    routes_text = (API_ROOT / "v1" / "attack_patterns.py").read_text()
    canonical_handlers = [
        "get_attack_pattern",
        "add_detection_guidance",
        "add_mitigation_reference",
        "add_procedure_example",
        "add_relationship",
        "deprecate_attack_pattern",
        "revoke_attack_pattern",
        "supersede_attack_pattern",
        "reactivate_attack_pattern",
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
            f"{name} must derive authorization from loaded AttackPattern ownership scope"
        )


def test_public_route_count_matches_approved_canonical_contract() -> None:
    """13 total: 2 explicit observation routes + 2 unambiguous list
    routes + 9 canonical single `{attack_pattern_id}` routes (get,
    detection-guidance, mitigation-references, procedure-examples,
    relationships, deprecate, revoke, supersede, reactivate)."""
    from redforge.app import create_app

    app = create_app()
    schema = app.openapi()
    ap_paths = [p for p in schema["paths"] if "/attack-patterns" in p]
    assert len(ap_paths) == 13, sorted(ap_paths)


def test_no_delete_endpoint() -> None:
    routes_text = (API_ROOT / "v1" / "attack_patterns.py").read_text()
    assert ".delete(" not in routes_text, "no delete endpoint is permitted"
