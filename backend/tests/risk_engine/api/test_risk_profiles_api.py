"""API integration tests for risk_engine risk-profile endpoints —
mirrors `tests/credential_vault/api/test_credentials_api.py`'s style
(real Postgres via `httpx.AsyncClient` against a real ASGI app)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.integration


def _signal_reference(
    *, subject_reference: str = "asset-123", raw_value: float = 7.5, source_id: str = "sig-1"
) -> dict[str, object]:
    return {
        "source_context": "vulnerability_engine",
        "source_aggregate_type": "ScanFinding",
        "source_id": source_id,
        "signal_type": "severity_rating",
        "raw_value": raw_value,
        "raw_scale": "cvss_0_10",
        "observed_at": datetime.now(UTC).isoformat(),
        "subject_reference": subject_reference,
    }


async def _create_profile(client: AsyncClient, **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "subject_reference": "asset-123",
        "dimension": "vulnerability",
        "signal_reference": _signal_reference(),
    }
    payload.update(overrides)
    response = await client.post("/api/v1/risk-profiles", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.asyncio
async def test_create_risk_profile_returns_201_with_location_header(
    async_client: AsyncClient,
) -> None:
    body = await _create_profile(async_client)
    response_location = f"/api/v1/risk-profiles/{body['profile_id']}"
    assert body["status"] == "open"
    assert body["subject_reference"] == "asset-123"
    assert body["contributions"][0]["dimension"] == "vulnerability"
    # Location header asserted via a fresh POST since httpx response
    # object above was already consumed into JSON.
    resp2 = await async_client.post(
        "/api/v1/risk-profiles",
        json={
            "subject_reference": "asset-456",
            "dimension": "cloud",
            "signal_reference": _signal_reference(subject_reference="asset-456"),
        },
    )
    assert resp2.headers["location"] == f"/api/v1/risk-profiles/{resp2.json()['profile_id']}"
    assert response_location != resp2.headers["location"]


@pytest.mark.asyncio
async def test_get_risk_profile_returns_created_profile(async_client: AsyncClient) -> None:
    created = await _create_profile(async_client)
    response = await async_client.get(f"/api/v1/risk-profiles/{created['profile_id']}")
    assert response.status_code == 200
    assert response.json()["profile_id"] == created["profile_id"]


@pytest.mark.asyncio
async def test_get_risk_profile_returns_404_when_missing(async_client: AsyncClient) -> None:
    response = await async_client.get("/api/v1/risk-profiles/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_risk_profile_cross_tenant_returns_404(
    async_client: AsyncClient, other_tenant_client: AsyncClient
) -> None:
    created = await _create_profile(async_client)
    response = await other_tenant_client.get(f"/api/v1/risk-profiles/{created['profile_id']}")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_list_risk_profiles_filters_by_status(async_client: AsyncClient) -> None:
    await _create_profile(async_client, subject_reference="asset-list-1")
    response = await async_client.get(
        "/api/v1/risk-profiles", params={"status": "open", "limit": 10}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 1
    assert all(item["status"] == "open" for item in body["items"])


@pytest.mark.asyncio
async def test_risk_profile_lifecycle_acknowledge_mitigate_close(
    async_client: AsyncClient,
) -> None:
    created = await _create_profile(async_client, subject_reference="asset-lifecycle")
    profile_id = created["profile_id"]

    ack = await async_client.post(f"/api/v1/risk-profiles/{profile_id}/acknowledge")
    assert ack.status_code == 200
    assert ack.json()["status"] == "acknowledged"

    mitigated = await async_client.post(f"/api/v1/risk-profiles/{profile_id}/mitigate")
    assert mitigated.status_code == 200
    assert mitigated.json()["status"] == "mitigated"

    closed = await async_client.post(f"/api/v1/risk-profiles/{profile_id}/close")
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"


@pytest.mark.asyncio
async def test_recompute_risk_profile_returns_composite_score(
    async_client: AsyncClient,
) -> None:
    created = await _create_profile(async_client, subject_reference="asset-recompute")
    profile_id = created["profile_id"]

    response = await async_client.post(
        f"/api/v1/risk-profiles/{profile_id}/recompute",
        json={
            "signals": [
                {"dimension": "vulnerability", "signal_reference": _signal_reference()},
                {
                    "dimension": "cloud",
                    "signal_reference": _signal_reference(raw_value=4.0, source_id="sig-2"),
                },
            ],
            "weight_profile": {
                "profile_name": "default",
                "version": 1,
                "weights": {"vulnerability": 1.0, "cloud": 1.0},
            },
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["composite_score"] is not None


@pytest.mark.asyncio
async def test_risk_profile_timeline_reflects_recompute(async_client: AsyncClient) -> None:
    created = await _create_profile(async_client, subject_reference="asset-timeline")
    profile_id = created["profile_id"]
    await async_client.post(
        f"/api/v1/risk-profiles/{profile_id}/recompute",
        json={
            "signals": [
                {"dimension": "vulnerability", "signal_reference": _signal_reference()},
            ],
            "weight_profile": {
                "profile_name": "default",
                "version": 1,
                "weights": {"vulnerability": 1.0},
            },
        },
    )
    response = await async_client.get(f"/api/v1/risk-profiles/{profile_id}/timeline")
    assert response.status_code == 200
    body = response.json()
    assert body["profile_id"] == profile_id
    assert body["trend_direction"] in {"increasing", "decreasing", "stable", "volatile"}


@pytest.mark.asyncio
async def test_accept_risk_profile_sets_accepted_expires_at(async_client: AsyncClient) -> None:
    created = await _create_profile(async_client, subject_reference="asset-accept")
    profile_id = created["profile_id"]
    expires_at = "2099-01-01T00:00:00+00:00"
    response = await async_client.post(
        f"/api/v1/risk-profiles/{profile_id}/accept",
        json={"expires_at": expires_at},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "accepted"
    assert response.json()["accepted_expires_at"] is not None
