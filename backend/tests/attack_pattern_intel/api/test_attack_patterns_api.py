"""API integration tests for attack_pattern_intel (real HTTP calls via
httpx ASGI transport, real PostgreSQL persistence)."""

from __future__ import annotations

import random

import pytest
import pytest_asyncio

from tests.attack_pattern_intel.infrastructure.helpers import seed_attack_technique

pytestmark = pytest.mark.integration

# Tenant-scoped test technique_ids are safe to hardcode (each test uses
# a fresh, randomly-generated tenant_id, so identity never collides
# across runs even against a long-lived shared database). The two
# GLOBAL-scope technique_ids below must be unique per test run instead
# — the global scope is shared across every run against the same
# database, so a fixed id would collide with a prior run's leftover
# global row.
_TENANT_TECHNIQUE_IDS = (
    "T1059",
    "T1078",
    "T1055",
    "T1071",
    "T1204",
    "T1218",
    "T1548",
)
_GLOBAL_TECHNIQUE_ID_OBSERVE = f"T{random.randint(2000, 2499)}"
_GLOBAL_TECHNIQUE_ID_LIST = f"T{random.randint(2500, 2999)}"
_TECHNIQUE_IDS = (*_TENANT_TECHNIQUE_IDS, _GLOBAL_TECHNIQUE_ID_OBSERVE, _GLOBAL_TECHNIQUE_ID_LIST)


@pytest_asyncio.fixture(autouse=True)
async def _seed_known_techniques(ap_api_session_factory) -> None:
    """Seeds the real, canonical `attack_techniques` table (M22) with
    every technique_id these API tests reference — the ACL port
    validates existence against real data, never a stub, so the test
    fixture itself is the "approved shared feed" precondition."""
    session = ap_api_session_factory()
    try:
        for technique_id in _TECHNIQUE_IDS:
            await seed_attack_technique(session, technique_id)
        await session.commit()
    finally:
        await session.close()


def _observe_body(technique_id: str = "T1059") -> dict:
    return {"technique_id": technique_id, "sub_technique_id": None}


def _attribution() -> dict:
    return {
        "source_system": "redforge-analyst",
        "reference": "ref-1",
        "observed_at": "2026-08-05T00:00:00+00:00",
    }


@pytest.mark.asyncio
async def test_observe_tenant_attack_pattern_and_get(owner_client) -> None:
    resp = await owner_client.post(
        "/api/v1/attack-patterns/observations/tenant", json=_observe_body("T1059")
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["technique_id"] == "T1059"
    assert body["lifecycle_status"] == "active"

    get_resp = await owner_client.get(f"/api/v1/attack-patterns/{body['attack_pattern_id']}")
    assert get_resp.status_code == 200
    assert get_resp.json()["attack_pattern_id"] == body["attack_pattern_id"]


@pytest.mark.asyncio
async def test_observe_tenant_duplicate_rejected(owner_client) -> None:
    first = await owner_client.post(
        "/api/v1/attack-patterns/observations/tenant", json=_observe_body("T1078")
    )
    assert first.status_code == 201
    second = await owner_client.post(
        "/api/v1/attack-patterns/observations/tenant", json=_observe_body("T1078")
    )
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_observe_tenant_requires_permission(no_permission_client) -> None:
    resp = await no_permission_client.post(
        "/api/v1/attack-patterns/observations/tenant", json=_observe_body("T1055")
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_observe_global_requires_platform_permission(owner_client) -> None:
    """An organization OWNER (full tenant permissions) cannot observe a
    global AttackPattern — only real platform authority can."""
    resp = await owner_client.post(
        "/api/v1/attack-patterns/observations/global", json=_observe_body("T1055")
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_observe_global_succeeds_with_platform_authority(platform_admin_client) -> None:
    resp = await platform_admin_client.post(
        "/api/v1/attack-patterns/observations/global",
        json=_observe_body(_GLOBAL_TECHNIQUE_ID_OBSERVE),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["tenant_id"] is None


@pytest.mark.asyncio
async def test_cross_tenant_get_returns_not_found(owner_client, other_tenant_client) -> None:
    created = await owner_client.post(
        "/api/v1/attack-patterns/observations/tenant", json=_observe_body("T1071")
    )
    attack_pattern_id = created.json()["attack_pattern_id"]

    resp = await other_tenant_client.get(f"/api/v1/attack-patterns/{attack_pattern_id}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_missing_pattern_returns_404(owner_client) -> None:
    import uuid

    resp = await owner_client.get(f"/api/v1/attack-patterns/{uuid.uuid4()}")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_full_observe_guidance_lifecycle_workflow(owner_client) -> None:
    created = await owner_client.post(
        "/api/v1/attack-patterns/observations/tenant", json=_observe_body("T1204")
    )
    assert created.status_code == 201
    attack_pattern_id = created.json()["attack_pattern_id"]

    guidance_resp = await owner_client.post(
        f"/api/v1/attack-patterns/{attack_pattern_id}/detection-guidance",
        json={"content": "Watch for X", "attribution": _attribution()},
    )
    assert guidance_resp.status_code == 200
    assert len(guidance_resp.json()["detection_guidance"]) == 1

    deprecate_resp = await owner_client.patch(
        f"/api/v1/attack-patterns/{attack_pattern_id}/deprecate",
        json={"evidence": _attribution()},
    )
    assert deprecate_resp.status_code == 200
    assert deprecate_resp.json()["lifecycle_status"] == "deprecated"

    revoke_resp = await owner_client.patch(
        f"/api/v1/attack-patterns/{attack_pattern_id}/revoke",
        json={"evidence": _attribution()},
    )
    assert revoke_resp.status_code == 200
    assert revoke_resp.json()["lifecycle_status"] == "revoked"

    # REVOKED is terminal — a further transition is illegal (409).
    reactivate_resp = await owner_client.patch(
        f"/api/v1/attack-patterns/{attack_pattern_id}/reactivate",
        json={"evidence": _attribution()},
    )
    assert reactivate_resp.status_code == 409


@pytest.mark.asyncio
async def test_manage_requires_manage_permission(owner_client, no_permission_client) -> None:
    created = await owner_client.post(
        "/api/v1/attack-patterns/observations/tenant", json=_observe_body("T1218")
    )
    attack_pattern_id = created.json()["attack_pattern_id"]

    resp = await no_permission_client.patch(
        f"/api/v1/attack-patterns/{attack_pattern_id}/deprecate",
        json={"evidence": _attribution()},
    )
    # no_permission_client is a different tenant with no permissions —
    # cross-tenant ownership check yields 404 before a 403 would ever
    # be considered, matching the ownership-based authorization
    # decision tree (see `_authorize_scope`).
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_list_tenant_attack_patterns(owner_client) -> None:
    await owner_client.post(
        "/api/v1/attack-patterns/observations/tenant", json=_observe_body("T1548")
    )
    resp = await owner_client.get("/api/v1/attack-patterns")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] >= 1
    assert any(item["technique_id"] == "T1548" for item in body["items"])


@pytest.mark.asyncio
async def test_list_global_requires_platform_permission(owner_client) -> None:
    resp = await owner_client.get("/api/v1/attack-patterns/global")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_global_succeeds_with_platform_authority(platform_admin_client) -> None:
    await platform_admin_client.post(
        "/api/v1/attack-patterns/observations/global", json=_observe_body(_GLOBAL_TECHNIQUE_ID_LIST)
    )
    resp = await platform_admin_client.get("/api/v1/attack-patterns/global")
    assert resp.status_code == 200
    assert resp.json()["count"] >= 1
