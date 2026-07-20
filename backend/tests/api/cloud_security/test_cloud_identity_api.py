"""API tests for M26 Phase 3 cloud identity endpoints."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from redforge.api.security import TenantContext, get_tenant_context
from redforge.api.v1.cloud_identity import router as cloud_identity_router
from redforge.application.cloud_security.identity_dtos import (
    CloudIAMPrincipalDTO,
    CloudIAMPrincipalPageDTO,
    IdentityDiscoveryResultDTO,
    PolicyAttachmentDTO,
    TrustRelationshipDTO,
)
from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole
from redforge.infrastructure.middleware.error_handler import ErrorHandlerMiddleware


class _FakeIdentityService:
    def __init__(self) -> None:
        self.principals: list[CloudIAMPrincipalDTO] = []
        now = datetime.now(UTC)
        self.principals.append(
            CloudIAMPrincipalDTO(
                principal_id=str(uuid4()),
                cloud_account_id=str(uuid4()),
                organization_id="01HXORG0000000000000000001",
                principal_type="ROLE",
                provider_id="arn:aws:iam::111122223333:role/api",
                display_name="api",
                privilege_level="NONE",
                is_federated=False,
                is_human=False,
                is_disabled=False,
                is_deleted=False,
                last_activity_at=None,
                last_seen_at=now,
                first_seen_at=now,
                created_at=now,
                updated_at=now,
                version=1,
                attached_policies=[
                    PolicyAttachmentDTO(
                        attachment_id=str(uuid4()),
                        policy_provider_id="arn:aws:iam::aws:policy/ReadOnlyAccess",
                        policy_name="ReadOnlyAccess",
                        attachment_type="MANAGED",
                        is_inline=False,
                    )
                ],
                trust_relationships=[
                    TrustRelationshipDTO(
                        trust_id=str(uuid4()),
                        trusted_principal_provider_id="ec2.amazonaws.com",
                        trust_type="AssumeRole",
                        is_cross_account=False,
                        conditions=[],
                    )
                ],
            )
        )

    async def discover_account(self, command: Any) -> IdentityDiscoveryResultDTO:
        return IdentityDiscoveryResultDTO(
            cloud_account_id=command.cloud_account_id,
            organization_id=command.organization_id,
            sync_status="SYNCED",
            discovered_count=1,
            updated_count=0,
            resurrected_count=0,
            deleted_count=0,
            projected_count=1,
        )

    async def list_principals(self, query: Any) -> CloudIAMPrincipalPageDTO:
        return CloudIAMPrincipalPageDTO(
            items=self.principals,
            page=query.page,
            size=query.size,
            total=len(self.principals),
        )

    async def get_principal(self, query: Any) -> CloudIAMPrincipalDTO:
        return self.principals[0]

    async def list_attached_policies(self, query: Any) -> list[PolicyAttachmentDTO]:
        return list(self.principals[0].attached_policies)

    async def list_trust_relationships(self, query: Any) -> list[TrustRelationshipDTO]:
        return list(self.principals[0].trust_relationships)


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    application.add_middleware(ErrorHandlerMiddleware)
    application.include_router(cloud_identity_router, prefix="/api/v1")
    fake = _FakeIdentityService()

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

    from redforge.api.dependencies import (
        get_identity_discovery_service,
        get_organization_service,
    )

    application.dependency_overrides[get_tenant_context] = _tenant
    application.dependency_overrides[get_identity_discovery_service] = lambda: fake
    application.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    return application


@pytest.mark.asyncio
async def test_identity_discovery_and_principal_apis(app: FastAPI) -> None:
    account_id = uuid4()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        discover = await client.post(
            f"/api/v1/cloud-foundation/accounts/{account_id}/discover-identity"
        )
        assert discover.status_code == 200
        body = discover.json()
        assert body["discovered_count"] == 1
        assert body["sync_status"] == "SYNCED"

        listed = await client.get("/api/v1/cloud-foundation/iam/principals")
        assert listed.status_code == 200
        assert listed.json()["total"] == 1

        principal_id = listed.json()["items"][0]["principal_id"]
        detail = await client.get(f"/api/v1/cloud-foundation/iam/principals/{principal_id}")
        assert detail.status_code == 200
        assert detail.json()["provider_id"].endswith(":role/api")

        policies = await client.get(
            f"/api/v1/cloud-foundation/iam/principals/{principal_id}/policies"
        )
        assert policies.status_code == 200
        assert policies.json()[0]["attachment_type"] == "MANAGED"

        trusts = await client.get(f"/api/v1/cloud-foundation/iam/principals/{principal_id}/trusts")
        assert trusts.status_code == 200
        assert trusts.json()[0]["trust_type"] == "AssumeRole"
