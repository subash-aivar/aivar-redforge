"""Execution API tests — kill switch, journal, and worker endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from httpx import AsyncClient

from execution.domain.value_objects.enums import KillSwitchArmedState, KillSwitchScope
from execution.domain.value_objects.identifiers import EngagementId, TenantId


@pytest.mark.asyncio
async def test_trigger_and_get_kill_switch(
    async_client: AsyncClient, api_engagement_id: UUID
) -> None:
    resp = await async_client.post(
        "/api/v1/kill-switches",
        json={
            "scope": KillSwitchScope.ENGAGEMENT.value,
            "scope_ref": str(api_engagement_id),
            "authority_role": "redteam:admin",
            "reason": "api emergency stop",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["armed_state"] == KillSwitchArmedState.TRIGGERED.value
    assert body["scope"] == KillSwitchScope.ENGAGEMENT.value

    get_resp = await async_client.get(
        f"/api/v1/kill-switches/{KillSwitchScope.ENGAGEMENT.value}/{api_engagement_id}"
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["armed_state"] == KillSwitchArmedState.TRIGGERED.value


@pytest.mark.asyncio
async def test_release_same_operator_rejected_via_api(
    async_client: AsyncClient, api_engagement_id: UUID
) -> None:
    trigger = await async_client.post(
        "/api/v1/kill-switches",
        json={
            "scope": KillSwitchScope.ENGAGEMENT.value,
            "scope_ref": str(api_engagement_id),
            "authority_role": "redteam:admin",
            "reason": "stop",
        },
    )
    assert trigger.status_code == 201
    release = await async_client.post(
        "/api/v1/kill-switches/release",
        json={
            "scope": KillSwitchScope.ENGAGEMENT.value,
            "scope_ref": str(api_engagement_id),
            "releasing_role": "redteam:admin",
        },
    )
    assert release.status_code in {403, 409, 422}


@pytest.mark.asyncio
async def test_journal_integrity_endpoint(
    async_client: AsyncClient,
    api_engagement_id: UUID,
    execution_app_service: tuple,
    api_tenant_id: UUID,
) -> None:
    svc, _, _ = execution_app_service
    await svc.ensure_journal_for_engagement(
        TenantId(api_tenant_id),
        EngagementId(api_engagement_id),
        datetime.now(UTC),
    )
    integrity = await async_client.get(
        f"/api/v1/execution-journals/{api_engagement_id}/integrity"
    )
    assert integrity.status_code == 200
    assert integrity.json()["status"] == "Verified"


@pytest.mark.asyncio
async def test_register_execution_worker(async_client: AsyncClient) -> None:
    resp = await async_client.post(
        "/api/v1/execution-workers",
        json={
            "worker_type": "CloudAgent",
            "trust_level": "HighTrust",
            "network_zone": "dmz",
            "techniques": ["T1059"],
            "signature": "admin-signed-manifest",
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["worker_type"] == "CloudAgent"
    assert "T1059" in body["capabilities"]
    assert body["health_status"] == "Healthy"
