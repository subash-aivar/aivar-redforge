"""RBAC role-boundary tests for threat_actor_intel (M51.1 Phase 4.5).

Every client here holds the REAL, product-defined permission set for
its `MembershipRole` (via `ROLE_PERMISSIONS`), not a hand-picked
subset — these tests prove the actual, shipped role policy, not an
idealized one. Final matrix (see `Permission.THREAT_INTEL_*`'s
docstring in `redforge.domain.identity.value_objects` for the
explicit reasoning):

- VIEWER:            THREAT_INTEL_READ only
- MEMBER:             + THREAT_INTEL_ASSOCIATE
- ANALYST:            + THREAT_INTEL_ASSOCIATE
- SECURITY_MANAGER:   + THREAT_INTEL_ADMIN (full)
- ADMIN:              + THREAT_INTEL_ADMIN (full)
- OWNER:              everything
"""

from __future__ import annotations

import pytest

from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.security_conditions.ingestion import SecurityConditionInput
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.domain.inventory.identity import IdentityScheme
from redforge.domain.inventory.value_objects import AssetDiscoverySource, AssetType
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.integration


async def _real_security_condition_id(session_factory, organization_id: str) -> str:
    asset_service = TenantAssetService(session_factory)
    asset = await asset_service.resolve_asset(
        organization_id=organization_id,
        asset_type=AssetType.HOST,
        scheme=IdentityScheme.DISCOVERY_HOST,
        raw_external_id=f"{EntityId.generate()}:{EntityId.generate()}",
        name="test-host",
        description="",
        discovery_source=AssetDiscoverySource.API_SCAN,
    )
    condition_service = TenantSecurityConditionService(session_factory)
    condition = await condition_service.ingest(
        SecurityConditionInput(
            organization_id=organization_id,
            affected_asset_id=asset.id,
            source_category="network_discovery",
            stable_rule_id="SENSITIVE_SERVICE_OBSERVED",
            evidence_state="observed",
            severity="medium",
            title="Sensitive service observed",
            summary="SSH observed on host.",
        )
    )
    return condition.id


async def _register_actor(async_client, name: str = "APT29") -> dict:
    response = await async_client.post(
        "/api/v1/threat-actors",
        json={
            "name": name,
            "origin": "nation_state",
            "motivations": ["espionage"],
            "sophistication": "expert",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


@pytest.mark.asyncio
async def test_viewer_cannot_associate(async_client, role_viewer_client) -> None:
    registered = await _register_actor(async_client)
    client, _org_id = role_viewer_client
    response = await client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations",
        json={
            "referenced_entity_type": "SecurityCondition",
            "referenced_entity_id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "evidence_citation": "citation",
        },
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_analyst_can_associate(async_client, analyst_client, tai_api_session_factory) -> None:
    registered = await _register_actor(async_client)
    client, org_id = analyst_client
    condition_id = await _real_security_condition_id(tai_api_session_factory, str(org_id))
    response = await client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations",
        json={
            "referenced_entity_type": "SecurityCondition",
            "referenced_entity_id": condition_id,
            "evidence_citation": "analyst-created association",
        },
    )
    assert response.status_code == 201, response.text


@pytest.mark.asyncio
async def test_member_can_associate_per_final_policy(
    async_client, member_client, tai_api_session_factory
) -> None:
    """Explicit final policy decision (Phase 4.5 RBAC review): MEMBER
    holds THREAT_INTEL_ASSOCIATE, mirroring the existing
    VALIDATIONS_RUN/AUTHORIZATIONS_CREATE precedent for a reversible,
    tenant-scoped operational action."""
    registered = await _register_actor(async_client)
    client, org_id = member_client
    condition_id = await _real_security_condition_id(tai_api_session_factory, str(org_id))
    response = await client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations",
        json={
            "referenced_entity_type": "SecurityCondition",
            "referenced_entity_id": condition_id,
            "evidence_citation": "member-created association",
        },
    )
    assert response.status_code == 201, response.text


@pytest.mark.asyncio
async def test_member_can_retract_own_association(
    async_client, member_client, tai_api_session_factory
) -> None:
    registered = await _register_actor(async_client)
    client, org_id = member_client
    condition_id = await _real_security_condition_id(tai_api_session_factory, str(org_id))
    created = await client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations",
        json={
            "referenced_entity_type": "SecurityCondition",
            "referenced_entity_id": condition_id,
            "evidence_citation": "member-created association",
        },
    )
    association_id = created.json()["association_id"]
    response = await client.delete(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations/{association_id}"
    )
    assert response.status_code == 204


@pytest.mark.asyncio
async def test_analyst_cannot_mutate_global_actor(async_client, analyst_client) -> None:
    registered = await _register_actor(async_client)
    client, _org_id = analyst_client
    response = await client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/aliases",
        json={"alias": "Cozy Bear"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_member_cannot_mutate_global_actor(async_client, member_client) -> None:
    registered = await _register_actor(async_client)
    client, _org_id = member_client
    response = await client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/aliases",
        json={"alias": "Cozy Bear"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_viewer_cannot_mutate_global_actor(async_client, role_viewer_client) -> None:
    registered = await _register_actor(async_client)
    client, _org_id = role_viewer_client
    response = await client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/aliases",
        json={"alias": "Cozy Bear"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_mutate_global_actor(async_client, admin_client) -> None:
    registered = await _register_actor(async_client)
    client, _org_id = admin_client
    response = await client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/aliases",
        json={"alias": "Cozy Bear"},
    )
    assert response.status_code == 200, response.text


@pytest.mark.asyncio
async def test_admin_can_register_global_actor(admin_client) -> None:
    client, _org_id = admin_client
    response = await client.post(
        "/api/v1/threat-actors",
        json={
            "name": "APT-Admin-Registered",
            "origin": "nation_state",
            "motivations": ["espionage"],
            "sophistication": "expert",
        },
    )
    assert response.status_code == 201, response.text


@pytest.mark.asyncio
async def test_viewer_can_read(async_client, role_viewer_client) -> None:
    await _register_actor(async_client)
    client, _org_id = role_viewer_client
    response = await client.get("/api/v1/threat-actors")
    assert response.status_code == 200


@pytest.mark.asyncio
async def test_viewer_can_list_own_tenant_associations(role_viewer_client) -> None:
    client, _org_id = role_viewer_client
    response = await client.get(
        "/api/v1/threat-actors/00000000-0000-0000-0000-000000000001/associations"
    )
    # 200 with empty results (VIEWER holds THREAT_INTEL_READ) — never 403.
    assert response.status_code == 200
