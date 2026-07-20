"""API tests for M26 Phase 6 Runtime Visibility endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from redforge.api.security import TenantContext, get_tenant_context
from redforge.api.v1.cloud_runtime import router as cloud_runtime_router
from redforge.application.cloud_security.runtime.dtos import (
    IngestResultDTO,
    RuntimeEventDTO,
    RuntimeNetworkConnectionDTO,
    RuntimeProcessDTO,
    RuntimeSummaryDTO,
)
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware

ORG = "01HXORG0000000000000000001"
ACCOUNT = uuid4()
EVENT = uuid4()
NOW = datetime.now(UTC)


def _event_dto() -> RuntimeEventDTO:
    return RuntimeEventDTO(
        event_id=str(EVENT),
        organization_id=ORG,
        cloud_account_id=str(ACCOUNT),
        event_type="API_ACTIVITY",
        source="CLOUDTRAIL",
        severity="INFO",
        outcome="SUCCESS",
        event_time=NOW,
        ingested_at=NOW,
        event_name="DescribeInstances",
        provider_event_id="prov-1",
        source_ip="1.2.3.4",
        target_resource="i-abc",
        identity={"principal_id": "p1"},
        host={},
        container={},
        correlation_refs={"organization_id": ORG},
        cspm_snapshot={"asset_type": "RUNTIME_EVENT"},
        created_at=NOW,
        updated_at=NOW,
    )


class _FakeIngestion:
    async def ingest(self, command: Any) -> IngestResultDTO:
        return IngestResultDTO(
            organization_id=command.organization_id,
            accepted=len(command.events),
            inserted=len(command.events),
            skipped_duplicates=0,
            event_ids=[str(EVENT)],
        )


class _FakeQuery:
    async def list_events(self, organization_id: str, **kwargs: Any) -> list[RuntimeEventDTO]:
        return [_event_dto()]

    async def get_event(self, organization_id: str, event_id: Any) -> RuntimeEventDTO:
        return _event_dto()

    async def list_processes(
        self, organization_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[RuntimeProcessDTO]:
        return [
            RuntimeProcessDTO(
                process_id=str(uuid4()),
                organization_id=ORG,
                runtime_event_id=str(EVENT),
                process_name="bash",
                executable_path="/bin/bash",
                pid=1,
                parent_pid=0,
                command_line="bash",
                user_name="root",
                created_at=NOW,
            )
        ]

    async def list_network_connections(
        self, organization_id: str, *, limit: int = 100, offset: int = 0
    ) -> list[RuntimeNetworkConnectionDTO]:
        return [
            RuntimeNetworkConnectionDTO(
                connection_id=str(uuid4()),
                organization_id=ORG,
                runtime_event_id=str(EVENT),
                direction="OUTBOUND",
                protocol="TCP",
                local_address="10.0.0.1",
                local_port=1234,
                remote_address="8.8.8.8",
                remote_port=53,
                created_at=NOW,
            )
        ]

    async def summary(
        self, organization_id: str, *, since: Any = None
    ) -> RuntimeSummaryDTO:
        return RuntimeSummaryDTO(
            organization_id=ORG,
            total_events=1,
            by_event_type={"API_ACTIVITY": 1},
            by_source={"CLOUDTRAIL": 1},
            process_count=1,
            connection_count=1,
        )


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    application.add_middleware(ErrorHandlerMiddleware)
    application.include_router(cloud_runtime_router, prefix="/api/v1")

    async def _tenant() -> TenantContext:
        return TenantContext(
            user_id="01HXUSER000000000000000001",
            email="owner@example.com",
            organization_id=ORG,
            role=MembershipRole.OWNER,
            permissions=frozenset(ROLE_PERMISSIONS[MembershipRole.OWNER]),
        )

    class _OrgStub:
        async def get_by_id(self, organization_id: str) -> object:
            class _Org:
                status = "active"

            return _Org()

    from redforge.api.dependencies import (
        get_organization_service,
        get_runtime_ingestion_service,
        get_runtime_query_service,
    )

    application.dependency_overrides[get_tenant_context] = _tenant
    application.dependency_overrides[get_runtime_ingestion_service] = lambda: _FakeIngestion()
    application.dependency_overrides[get_runtime_query_service] = lambda: _FakeQuery()
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    return application


@pytest.fixture
async def client(app: FastAPI) -> AsyncClient:
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_ingest_runtime_events(client: AsyncClient) -> None:
    resp = await client.post(
        "/api/v1/cloud-foundation/runtime/events/ingest",
        json={
            "cloud_account_id": str(ACCOUNT),
            "source": "CLOUDTRAIL",
            "events": [
                {
                    "event_id": "e1",
                    "event_name": "DescribeInstances",
                    "event_time": NOW.isoformat(),
                }
            ],
        },
    )
    assert resp.status_code == 201
    body = resp.json()
    assert body["accepted"] == 1
    assert body["inserted"] == 1


@pytest.mark.asyncio
async def test_list_runtime_events(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/cloud-foundation/runtime/events")
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["event_name"] == "DescribeInstances"


@pytest.mark.asyncio
async def test_get_runtime_event(client: AsyncClient) -> None:
    resp = await client.get(f"/api/v1/cloud-foundation/runtime/events/{EVENT}")
    assert resp.status_code == 200
    assert resp.json()["event_id"] == str(EVENT)


@pytest.mark.asyncio
async def test_list_processes(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/cloud-foundation/runtime/processes")
    assert resp.status_code == 200
    assert resp.json()[0]["process_name"] == "bash"


@pytest.mark.asyncio
async def test_list_network_connections(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/cloud-foundation/runtime/network-connections")
    assert resp.status_code == 200
    assert resp.json()[0]["protocol"] == "TCP"


@pytest.mark.asyncio
async def test_runtime_summary(client: AsyncClient) -> None:
    resp = await client.get("/api/v1/cloud-foundation/runtime/summary")
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_events"] == 1
    assert body["process_count"] == 1
