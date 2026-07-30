"""API integration tests for attack_surface_management asset
endpoints — mirrors `tests/risk_engine/api/test_risk_profiles_api.py`'s
style (real Postgres via `httpx.AsyncClient` against a real ASGI app)."""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from httpx import AsyncClient

pytestmark = pytest.mark.integration


async def _register_asset(client: AsyncClient, **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "asset_type": "internet_facing",
        "domain_name": "example.com",
        "discovery_source": "manual_entry",
    }
    payload.update(overrides)
    response = await client.post("/api/v1/attack-surface-management/assets", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.asyncio
async def test_register_asset_returns_201_with_location_header(
    async_client: AsyncClient,
) -> None:
    body = await _register_asset(async_client)
    assert body["asset_type"] == "internet_facing"
    assert body["domain_name"] == "example.com"
    assert body["lifecycle_state"] == "discovered"

    resp2 = await async_client.post(
        "/api/v1/attack-surface-management/assets",
        json={
            "asset_type": "internal",
            "ip_address": "10.0.0.5",
            "discovery_source": "active_scan",
        },
    )
    assert resp2.status_code == 201, resp2.text
    assert (
        resp2.headers["location"]
        == f"/api/v1/attack-surface-management/assets/{resp2.json()['asset_id']}"
    )


@pytest.mark.asyncio
async def test_register_asset_without_identifier_returns_422(async_client: AsyncClient) -> None:
    response = await async_client.post(
        "/api/v1/attack-surface-management/assets",
        json={"asset_type": "internet_facing"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_asset_returns_registered_asset(async_client: AsyncClient) -> None:
    created = await _register_asset(async_client, domain_name="get-asset.example.com")
    response = await async_client.get(
        f"/api/v1/attack-surface-management/assets/{created['asset_id']}"
    )
    assert response.status_code == 200
    assert response.json()["asset_id"] == created["asset_id"]


@pytest.mark.asyncio
async def test_get_asset_returns_404_when_missing(async_client: AsyncClient) -> None:
    response = await async_client.get(
        "/api/v1/attack-surface-management/assets/00000000-0000-0000-0000-000000000000"
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_asset_cross_tenant_returns_404(
    async_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    created = await _register_asset(async_client, domain_name="cross-tenant.example.com")
    response = await other_tenant_client.get(
        f"/api/v1/attack-surface-management/assets/{created['asset_id']}"
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_assets_filters_by_lifecycle_state(async_client: AsyncClient) -> None:
    await _register_asset(async_client, domain_name="list-filter.example.com")
    response = await async_client.get(
        "/api/v1/attack-surface-management/assets",
        params={"lifecycle_state": "discovered", "limit": 10},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 1
    assert all(item["lifecycle_state"] == "discovered" for item in body["items"])


@pytest.mark.asyncio
async def test_asset_port_lifecycle_record_and_close(async_client: AsyncClient) -> None:
    created = await _register_asset(async_client, domain_name="ports.example.com")
    asset_id = created["asset_id"]

    recorded = await async_client.post(
        f"/api/v1/attack-surface-management/assets/{asset_id}/ports",
        json={"port_number": 443, "protocol": "tcp"},
    )
    assert recorded.status_code == 200, recorded.text
    ports = recorded.json()["ports"]
    assert len(ports) == 1
    port_id = ports[0]["port_id"]
    assert ports[0]["state"] == "open"

    closed = await async_client.post(
        f"/api/v1/attack-surface-management/assets/{asset_id}/ports/{port_id}/close"
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["ports"][0]["state"] == "closed"


@pytest.mark.asyncio
async def test_asset_criticality_and_reclassify(async_client: AsyncClient) -> None:
    created = await _register_asset(async_client, domain_name="criticality.example.com")
    asset_id = created["asset_id"]

    set_crit = await async_client.post(
        f"/api/v1/attack-surface-management/assets/{asset_id}/criticality",
        json={"criticality": "critical"},
    )
    assert set_crit.status_code == 200
    assert set_crit.json()["criticality"] == "critical"

    reclassified = await async_client.post(
        f"/api/v1/attack-surface-management/assets/{asset_id}/reclassify",
        json={"classification": "production"},
    )
    assert reclassified.status_code == 200
    assert reclassified.json()["classification"] == "production"

    score = await async_client.get(
        f"/api/v1/attack-surface-management/assets/{asset_id}/criticality-score"
    )
    assert score.status_code == 200
    assert score.json()["asset_id"] == asset_id


@pytest.mark.asyncio
async def test_asset_evaluate_exposure(async_client: AsyncClient) -> None:
    created = await _register_asset(async_client, domain_name="exposure.example.com")
    asset_id = created["asset_id"]
    response = await async_client.post(
        f"/api/v1/attack-surface-management/assets/{asset_id}/evaluate-exposure"
    )
    assert response.status_code == 200
    assert "exposure_state" in response.json()


@pytest.mark.asyncio
async def test_asset_decommission(async_client: AsyncClient) -> None:
    created = await _register_asset(async_client, domain_name="decommission.example.com")
    asset_id = created["asset_id"]

    validated = await async_client.post(
        f"/api/v1/attack-surface-management/assets/{asset_id}/lifecycle",
        json={"new_state": "validated"},
    )
    assert validated.status_code == 200, validated.text

    active = await async_client.post(
        f"/api/v1/attack-surface-management/assets/{asset_id}/lifecycle",
        json={"new_state": "active"},
    )
    assert active.status_code == 200, active.text

    response = await async_client.post(
        f"/api/v1/attack-surface-management/assets/{asset_id}/decommission"
    )
    assert response.status_code == 200
    assert response.json()["lifecycle_state"] == "decommissioned"


@pytest.mark.asyncio
async def test_asset_endpoints_require_permission(async_client: AsyncClient, app: FastAPI) -> None:
    """No-permission tenant is rejected — mirrors risk_engine's
    authorization-review conclusion that every route enforces
    `require_permission` via `Depends`."""
    from redforge.api.security import TenantContext, get_tenant_context

    def no_permission_context() -> TenantContext:
        from redforge.domain.identity.value_objects import MembershipRole
        from redforge.shared.identifiers import EntityId

        return TenantContext(
            user_id=str(EntityId.generate()),
            email="no-perm@example.com",
            organization_id=str(EntityId.generate()),
            role=MembershipRole.VIEWER,
            permissions=frozenset(),
        )

    app.dependency_overrides[get_tenant_context] = no_permission_context
    response = await async_client.post(
        "/api/v1/attack-surface-management/assets",
        json={"asset_type": "internet_facing", "domain_name": "no-perm.example.com"},
    )
    assert response.status_code == 403
