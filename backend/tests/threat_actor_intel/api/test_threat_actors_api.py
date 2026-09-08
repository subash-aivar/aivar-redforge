"""Integration tests for the threat_actor_intel API (M51.1 Phase 4/4.5).
Association tests use a real `SecurityCondition` row (M51.1 Phase 4.5
— no seeded allow-list in production DI; the API layer proves the
real cross-context evidence-existence path end to end)."""

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
async def test_register_threat_actor(async_client) -> None:
    body = await _register_actor(async_client)
    assert body["name"] == "APT29"
    assert body["tenant_id"] is None
    assert body["status"] == "active"


@pytest.mark.asyncio
async def test_get_threat_actor(async_client) -> None:
    registered = await _register_actor(async_client)
    response = await async_client.get(f"/api/v1/threat-actors/{registered['threat_actor_id']}")
    assert response.status_code == 200
    assert response.json()["threat_actor_id"] == registered["threat_actor_id"]


@pytest.mark.asyncio
async def test_list_threat_actors(async_client) -> None:
    await _register_actor(async_client, name="Listed APT")
    response = await async_client.get("/api/v1/threat-actors")
    assert response.status_code == 200
    body = response.json()
    assert body["count"] >= 1
    assert any(i["name"] == "Listed APT" for i in body["items"])


@pytest.mark.asyncio
async def test_add_alias(async_client) -> None:
    registered = await _register_actor(async_client)
    response = await async_client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/aliases",
        json={"alias": "Cozy Bear"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["aliases"] == ["Cozy Bear"]


@pytest.mark.asyncio
async def test_add_technique(async_client) -> None:
    registered = await _register_actor(async_client)
    response = await async_client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/techniques",
        json={"technique_id": "T1566"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["technique_refs"] == ["T1566"]


@pytest.mark.asyncio
async def test_add_indicator(async_client) -> None:
    registered = await _register_actor(async_client)
    response = await async_client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/indicators",
        json={"indicator_id": "ind-1"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["indicator_refs"] == ["ind-1"]


@pytest.mark.asyncio
async def test_update_motivation(async_client) -> None:
    registered = await _register_actor(async_client)
    response = await async_client.patch(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/motivation",
        json={"motivations": ["financial"]},
    )
    assert response.status_code == 200, response.text
    assert response.json()["motivations"] == ["financial"]


@pytest.mark.asyncio
async def test_update_sophistication(async_client) -> None:
    registered = await _register_actor(async_client)
    response = await async_client.patch(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/sophistication",
        json={"sophistication": "innovator"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["sophistication"] == "innovator"


@pytest.mark.asyncio
async def test_transition_status(async_client) -> None:
    registered = await _register_actor(async_client)
    response = await async_client.patch(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/status",
        json={"target_status": "dormant"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "dormant"


@pytest.mark.asyncio
async def test_create_association(async_client, tai_api_session_factory, organization_id) -> None:
    registered = await _register_actor(async_client)
    condition_id = await _real_security_condition_id(tai_api_session_factory, str(organization_id))
    response = await async_client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations",
        json={
            "referenced_entity_type": "SecurityCondition",
            "referenced_entity_id": condition_id,
            "evidence_citation": "real security condition evidence chain",
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["state"] == "active"
    assert body["tenant_id"] == str(organization_id)


@pytest.mark.asyncio
async def test_retract_association(async_client, tai_api_session_factory, organization_id) -> None:
    registered = await _register_actor(async_client)
    condition_id = await _real_security_condition_id(tai_api_session_factory, str(organization_id))
    created = await async_client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations",
        json={
            "referenced_entity_type": "SecurityCondition",
            "referenced_entity_id": condition_id,
            "evidence_citation": "real security condition evidence chain",
        },
    )
    association_id = created.json()["association_id"]
    response = await async_client.delete(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations/{association_id}"
    )
    assert response.status_code == 204


@pytest.mark.asyncio
async def test_list_associations(async_client, tai_api_session_factory, organization_id) -> None:
    registered = await _register_actor(async_client)
    condition_id = await _real_security_condition_id(tai_api_session_factory, str(organization_id))
    await async_client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations",
        json={
            "referenced_entity_type": "SecurityCondition",
            "referenced_entity_id": condition_id,
            "evidence_citation": "real security condition evidence chain",
        },
    )
    response = await async_client.get(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations"
    )
    assert response.status_code == 200
    assert response.json()["count"] == 1


@pytest.mark.asyncio
async def test_unauthorized_register_denied(async_client, viewer_only_client) -> None:
    response = await viewer_only_client.post(
        "/api/v1/threat-actors",
        json={
            "name": "APT29",
            "origin": "nation_state",
            "motivations": ["espionage"],
            "sophistication": "expert",
        },
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_unauthorized_mutation_denied(async_client, viewer_only_client) -> None:
    registered = await _register_actor(async_client)
    response = await viewer_only_client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/aliases",
        json={"alias": "Cozy Bear"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_no_permission_read_denied(no_permission_client) -> None:
    response = await no_permission_client.get("/api/v1/threat-actors")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_tenant_isolation_enforced(
    async_client, other_tenant_client, tai_api_session_factory, organization_id
) -> None:
    registered = await _register_actor(async_client)
    condition_id = await _real_security_condition_id(tai_api_session_factory, str(organization_id))
    created = await async_client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations",
        json={
            "referenced_entity_type": "SecurityCondition",
            "referenced_entity_id": condition_id,
            "evidence_citation": "real security condition evidence chain",
        },
    )
    association_id = created.json()["association_id"]

    other_list = await other_tenant_client.get(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations"
    )
    assert other_list.json()["count"] == 0

    other_retract = await other_tenant_client.delete(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations/{association_id}"
    )
    assert other_retract.status_code == 404


@pytest.mark.asyncio
async def test_invalid_evidence_rejected(async_client) -> None:
    """No real SecurityCondition was created for this id — the real
    adapter must reject it, proving there is no allow-list fallback."""
    registered = await _register_actor(async_client)
    response = await async_client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations",
        json={
            "referenced_entity_type": "SecurityCondition",
            "referenced_entity_id": "01HZZZZZZZZZZZZZZZZZZZZZZZ",
            "evidence_citation": "fabricated citation",
        },
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_duplicate_association_rejected(
    async_client, tai_api_session_factory, organization_id
) -> None:
    registered = await _register_actor(async_client)
    condition_id = await _real_security_condition_id(tai_api_session_factory, str(organization_id))
    payload = {
        "referenced_entity_type": "SecurityCondition",
        "referenced_entity_id": condition_id,
        "evidence_citation": "real security condition evidence chain",
    }
    first = await async_client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations", json=payload
    )
    assert first.status_code == 201
    second = await async_client.post(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/associations", json=payload
    )
    assert second.status_code == 409


@pytest.mark.asyncio
async def test_invalid_payload_validation(async_client) -> None:
    response = await async_client.post(
        "/api/v1/threat-actors",
        json={"name": "", "origin": "nation_state", "motivations": [], "sophistication": "expert"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_not_found_mapping(async_client) -> None:
    response = await async_client.get("/api/v1/threat-actors/00000000-0000-0000-0000-000000000001")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_application_exception_mapping_invalid_transition(async_client) -> None:
    registered = await _register_actor(async_client)
    # ACTIVE -> ACTIVE is illegal (InvalidActivityStatusTransition -> 422).
    response = await async_client.patch(
        f"/api/v1/threat-actors/{registered['threat_actor_id']}/status",
        json={"target_status": "active"},
    )
    assert response.status_code == 422
