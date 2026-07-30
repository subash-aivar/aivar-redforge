"""API integration tests for attack_surface_management network-range
endpoints — mirrors `tests/attack_surface_management/api/test_assets_api.py`'s
style (real Postgres via `httpx.AsyncClient` against a real ASGI app)."""

from __future__ import annotations

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.integration


async def _form_network_range(client: AsyncClient, **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {"cidr": "10.10.0.0/24", "discovery_source": "manual_entry"}
    payload.update(overrides)
    response = await client.post("/api/v1/attack-surface-management/network-ranges", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.asyncio
async def test_form_network_range_returns_201_with_location_header(
    async_client: AsyncClient,
) -> None:
    body = await _form_network_range(async_client)
    assert body["cidr"] == "10.10.0.0/24"
    assert body["lifecycle_state"] == "discovered"

    resp2 = await async_client.post(
        "/api/v1/attack-surface-management/network-ranges",
        json={"cidr": "10.20.0.0/24", "discovery_source": "active_scan"},
    )
    assert resp2.status_code == 201, resp2.text
    assert (
        resp2.headers["location"]
        == f"/api/v1/attack-surface-management/network-ranges/{resp2.json()['range_id']}"
    )


@pytest.mark.asyncio
async def test_form_network_range_invalid_cidr_returns_422(async_client: AsyncClient) -> None:
    response = await async_client.post(
        "/api/v1/attack-surface-management/network-ranges",
        json={"cidr": "not-a-cidr"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_get_network_range_returns_created_range(async_client: AsyncClient) -> None:
    created = await _form_network_range(async_client, cidr="10.30.0.0/24")
    response = await async_client.get(
        f"/api/v1/attack-surface-management/network-ranges/{created['range_id']}"
    )
    assert response.status_code == 200
    assert response.json()["range_id"] == created["range_id"]


@pytest.mark.asyncio
async def test_get_network_range_returns_404_when_missing(async_client: AsyncClient) -> None:
    response = await async_client.get(
        "/api/v1/attack-surface-management/network-ranges/00000000-0000-0000-0000-000000000000"
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_network_range_cross_tenant_returns_404(
    async_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    created = await _form_network_range(async_client, cidr="10.40.0.0/24")
    response = await other_tenant_client.get(
        f"/api/v1/attack-surface-management/network-ranges/{created['range_id']}"
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_network_ranges_filters_by_lifecycle_state(async_client: AsyncClient) -> None:
    await _form_network_range(async_client, cidr="10.50.0.0/24")
    response = await async_client.get(
        "/api/v1/attack-surface-management/network-ranges",
        params={"lifecycle_state": "discovered", "limit": 10},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 1
    assert all(item["lifecycle_state"] == "discovered" for item in body["items"])


@pytest.mark.asyncio
async def test_network_range_lifecycle_activate_retire(async_client: AsyncClient) -> None:
    created = await _form_network_range(async_client, cidr="10.60.0.0/24")
    range_id = created["range_id"]

    activated = await async_client.post(
        f"/api/v1/attack-surface-management/network-ranges/{range_id}/activate"
    )
    assert activated.status_code == 200
    assert activated.json()["lifecycle_state"] == "active"

    retired = await async_client.post(
        f"/api/v1/attack-surface-management/network-ranges/{range_id}/retire"
    )
    assert retired.status_code == 200
    assert retired.json()["lifecycle_state"] == "retired"


@pytest.mark.asyncio
async def test_record_network_range_asset_count(async_client: AsyncClient) -> None:
    created = await _form_network_range(async_client, cidr="10.70.0.0/24")
    range_id = created["range_id"]

    response = await async_client.post(
        f"/api/v1/attack-surface-management/network-ranges/{range_id}/asset-count",
        json={"count": 12},
    )
    assert response.status_code == 200
    assert response.json()["asset_count"] == 12
