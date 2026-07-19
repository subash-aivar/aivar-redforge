"""API tests for M26 cloud foundation admin endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from redforge.api.security import TenantContext, get_tenant_context
from redforge.api.v1.cloud_foundation import router as cloud_foundation_router
from redforge.application.cloud_security.foundation_dtos import (
    CloudAccountDTO,
    CloudAccountPageDTO,
    CloudProviderDTO,
)
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware


class _FakeFoundationService:
    def __init__(self) -> None:
        self.providers: list[CloudProviderDTO] = []
        self.accounts: list[CloudAccountDTO] = []

    async def register_cloud_provider(self, command: Any) -> CloudProviderDTO:
        dto = CloudProviderDTO(
            provider_id=str(uuid4()),
            organization_id=command.organization_id,
            provider_type=command.provider_type.upper(),
            display_name=command.display_name,
            status="ACTIVE",
            polling_interval_seconds=command.polling_interval_seconds,
            region_filter=list(command.region_filter),
            service_filter=list(command.service_filter),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            version=1,
        )
        self.providers.append(dto)
        return dto

    async def update_cloud_provider(self, command: Any) -> CloudProviderDTO:
        current = self.providers[0]
        updated = CloudProviderDTO(
            provider_id=current.provider_id,
            organization_id=current.organization_id,
            provider_type=current.provider_type,
            display_name=command.display_name or current.display_name,
            status=current.status,
            polling_interval_seconds=(
                command.polling_interval_seconds or current.polling_interval_seconds
            ),
            region_filter=list(command.region_filter or current.region_filter),
            service_filter=list(command.service_filter or current.service_filter),
            created_at=current.created_at,
            updated_at=datetime.now(UTC),
            version=current.version + 1,
        )
        self.providers[0] = updated
        return updated

    async def disable_cloud_provider(self, command: Any) -> CloudProviderDTO:
        current = self.providers[0]
        updated = CloudProviderDTO(
            provider_id=current.provider_id,
            organization_id=current.organization_id,
            provider_type=current.provider_type,
            display_name=current.display_name,
            status="DISABLED",
            polling_interval_seconds=current.polling_interval_seconds,
            region_filter=current.region_filter,
            service_filter=current.service_filter,
            created_at=current.created_at,
            updated_at=datetime.now(UTC),
            version=current.version + 1,
        )
        self.providers[0] = updated
        return updated

    async def register_cloud_account(self, command: Any) -> CloudAccountDTO:
        dto = CloudAccountDTO(
            account_id=str(uuid4()),
            cloud_provider_id=command.cloud_provider_id,
            organization_id=command.organization_id,
            external_id=command.external_id,
            display_name=command.display_name,
            account_type=command.account_type.upper(),
            credential_reference_id=command.credential_reference_id,
            sync_status="PENDING",
            tags=dict(command.tags or {}),
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
            version=1,
        )
        self.accounts.append(dto)
        return dto

    async def list_cloud_providers(self, query: Any) -> list[CloudProviderDTO]:
        return list(self.providers)

    async def list_cloud_accounts(self, query: Any) -> CloudAccountPageDTO:
        return CloudAccountPageDTO(
            items=list(self.accounts),
            page=1,
            size=len(self.accounts),
            total=len(self.accounts),
        )


@pytest.fixture
def app_client() -> tuple[FastAPI, _FakeFoundationService]:
    app = FastAPI()
    app.add_middleware(ErrorHandlerMiddleware)
    app.include_router(cloud_foundation_router, prefix="/api/v1")
    fake = _FakeFoundationService()

    async def _tenant() -> TenantContext:
        return TenantContext(
            user_id="01HXUSER000000000000000001",
            email="owner@example.com",
            organization_id="01HXORG0000000000000000001",
            role=MembershipRole.OWNER,
            permissions=frozenset(ROLE_PERMISSIONS[MembershipRole.OWNER]),
        )

    class _OrgStub:
        async def get_by_id(self, organization_id: str) -> object:
            class _Org:
                status = "active"

            return _Org()

    from redforge.api.dependencies import get_cloud_foundation_service, get_organization_service

    app.dependency_overrides[get_tenant_context] = _tenant
    app.dependency_overrides[get_cloud_foundation_service] = lambda: fake
    app.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    return app, fake


@pytest.mark.asyncio
async def test_cloud_foundation_admin_api_lifecycle(
    app_client: tuple[FastAPI, _FakeFoundationService],
) -> None:
    app, fake = app_client
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        create = await client.post(
            "/api/v1/cloud-foundation/providers",
            json={
                "provider_type": "AWS",
                "display_name": "Primary",
                "polling_interval_seconds": 3600,
            },
        )
        assert create.status_code == 201
        provider_id = create.json()["provider_id"]

        listed = await client.get("/api/v1/cloud-foundation/providers")
        assert listed.status_code == 200
        assert len(listed.json()) == 1

        updated = await client.patch(
            f"/api/v1/cloud-foundation/providers/{provider_id}",
            json={"display_name": "Primary Updated"},
        )
        assert updated.status_code == 200
        assert updated.json()["display_name"] == "Primary Updated"

        account = await client.post(
            "/api/v1/cloud-foundation/accounts",
            json={
                "cloud_provider_id": provider_id,
                "external_id": "111122223333",
                "display_name": "Acct",
                "account_type": "STANDALONE",
                "credential_reference_id": "cred-ref-1",
            },
        )
        assert account.status_code == 201

        accounts = await client.get("/api/v1/cloud-foundation/accounts")
        assert accounts.status_code == 200
        assert accounts.json()["total"] == 1

        disabled = await client.post(f"/api/v1/cloud-foundation/providers/{provider_id}/disable")
        assert disabled.status_code == 200
        assert disabled.json()["status"] == "DISABLED"
        assert fake.providers[0].status == "DISABLED"
