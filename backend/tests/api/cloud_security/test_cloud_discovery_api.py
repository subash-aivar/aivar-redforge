"""API tests for M26 Phase 2 cloud discovery endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from redforge.api.security import TenantContext, get_tenant_context
from redforge.api.v1.cloud_discovery import router as cloud_discovery_router
from redforge.application.cloud_security.discovery_dtos import (
    AssetRelationshipDTO,
    CloudAssetDTO,
    CloudAssetPageDTO,
    DiscoveryResultDTO,
)
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware


class _FakeDiscoveryService:
    def __init__(self) -> None:
        self.assets: list[CloudAssetDTO] = []
        now = datetime.now(UTC)
        self.assets.append(
            CloudAssetDTO(
                asset_id=str(uuid4()),
                cloud_account_id=str(uuid4()),
                organization_id="01HXORG0000000000000000001",
                asset_type="EC2_INSTANCE",
                provider_id="i-api-1",
                display_name="api-web",
                region_code="us-east-1",
                az_name="us-east-1a",
                tags={"env": "test"},
                config_hash="abc",
                is_deleted=False,
                last_seen_at=now,
                first_seen_at=now,
                created_at=now,
                updated_at=now,
                version=1,
                relationships=[
                    AssetRelationshipDTO(
                        relationship_id=str(uuid4()),
                        relationship_type="CONTAINED_IN",
                        target_provider_id="vpc-1",
                        target_asset_id=None,
                    )
                ],
                normalized_config={"schema_version": "1", "resource_class": "compute"},
                provider_metadata={},
            )
        )

    async def discover_account(self, command: Any) -> DiscoveryResultDTO:
        return DiscoveryResultDTO(
            cloud_account_id=command.cloud_account_id,
            organization_id=command.organization_id,
            sync_status="SYNCED",
            discovered_count=1,
            updated_count=0,
            resurrected_count=0,
            deleted_count=0,
            projected_count=1,
        )

    async def list_cloud_assets(self, query: Any) -> CloudAssetPageDTO:
        return CloudAssetPageDTO(
            items=self.assets,
            page=query.page,
            size=query.size,
            total=len(self.assets),
        )

    async def get_cloud_asset(self, query: Any) -> CloudAssetDTO:
        return self.assets[0]

    async def list_asset_relationships(self, query: Any) -> list[AssetRelationshipDTO]:
        return list(self.assets[0].relationships)


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    application.add_middleware(ErrorHandlerMiddleware)
    application.include_router(cloud_discovery_router, prefix="/api/v1")
    fake = _FakeDiscoveryService()

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

    from redforge.api.dependencies import get_asset_discovery_service, get_organization_service

    application.dependency_overrides[get_tenant_context] = _tenant
    application.dependency_overrides[get_asset_discovery_service] = lambda: fake
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    return application


@pytest.mark.asyncio
async def test_discovery_and_asset_apis(app: FastAPI) -> None:
    account_id = uuid4()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        discover = await client.post(f"/api/v1/cloud-foundation/accounts/{account_id}/discover")
        assert discover.status_code == 200
        body = discover.json()
        assert body["discovered_count"] == 1
        assert body["sync_status"] == "SYNCED"

        listed = await client.get("/api/v1/cloud-foundation/assets")
        assert listed.status_code == 200
        assert listed.json()["total"] == 1

        asset_id = listed.json()["items"][0]["asset_id"]
        detail = await client.get(f"/api/v1/cloud-foundation/assets/{asset_id}")
        assert detail.status_code == 200
        assert detail.json()["provider_id"] == "i-api-1"

        rels = await client.get(f"/api/v1/cloud-foundation/assets/{asset_id}/relationships")
        assert rels.status_code == 200
        assert rels.json()[0]["relationship_type"] == "CONTAINED_IN"
