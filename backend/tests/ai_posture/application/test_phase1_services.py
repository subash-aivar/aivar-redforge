"""Application-layer tests for Phase 1 asset + shadow alert services."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from ai_posture.application.commands.posture_commands import (
    ApproveAISystemAssetRegistrationCommand,
    AssignAssetOwnerCommand,
    BulkResolveShadowAIAlertsCommand,
    BulkTriageShadowAIAlertsCommand,
    ClassifyAISystemAssetCommand,
    RaiseShadowAIAlertCommand,
    RegisterAISystemAssetCommand,
    SetDiscoveryOnlyModeCommand,
)
from ai_posture.application.exceptions import ApplicationForbiddenError
from ai_posture.domain.value_objects.identifiers import TenantId
from ai_posture.infrastructure.acl.degraded_adapters import StubInventoryQueryAdapter
from ai_posture.infrastructure.container import AIPostureContainer
from tests.ai_posture.conftest import ADMIN, ANALYST, APPROVER, ENGINEER, READER


@pytest.mark.asyncio
async def test_register_classify_approve_flow(
    container: AIPostureContainer,
    inventory: StubInventoryQueryAdapter,
    tenant_id: TenantId,
) -> None:
    asset_ref = uuid4()
    inventory.seed(asset_ref, tenant_id.value)
    dto = await container.asset_service.register(
        RegisterAISystemAssetCommand(
            tenant_id=tenant_id.value,
            asset_ref_id=asset_ref,
            discovery_source="ManualRegistration",
            actor_roles=ENGINEER,
        )
    )
    assert dto.lifecycle_state == "PendingClassification"
    asset_id = UUID(dto.asset_id)
    dto = await container.asset_service.classify(
        ClassifyAISystemAssetCommand(
            tenant_id=tenant_id.value,
            asset_id=asset_id,
            ai_system_kind="FoundationModelAPI",
            actor_roles=ENGINEER,
        )
    )
    assert dto.lifecycle_state == "UnderReview"
    dto = await container.asset_service.assign_owner(
        AssignAssetOwnerCommand(
            tenant_id=tenant_id.value,
            asset_id=asset_id,
            owner_id="owner-1",
            actor_roles=ENGINEER,
        )
    )
    dto = await container.asset_service.approve_registration(
        ApproveAISystemAssetRegistrationCommand(
            tenant_id=tenant_id.value, asset_id=asset_id, actor_roles=APPROVER
        )
    )
    assert dto.lifecycle_state == "Registered"


@pytest.mark.asyncio
async def test_register_idempotent_by_asset_ref(
    container: AIPostureContainer,
    inventory: StubInventoryQueryAdapter,
    tenant_id: TenantId,
) -> None:
    asset_ref = uuid4()
    inventory.seed(asset_ref, tenant_id.value)
    cmd = RegisterAISystemAssetCommand(
        tenant_id=tenant_id.value,
        asset_ref_id=asset_ref,
        discovery_source="ManualRegistration",
        actor_roles=ENGINEER,
    )
    a = await container.asset_service.register(cmd)
    b = await container.asset_service.register(cmd)
    assert a.asset_id == b.asset_id


@pytest.mark.asyncio
async def test_reader_cannot_register(
    container: AIPostureContainer,
    inventory: StubInventoryQueryAdapter,
    tenant_id: TenantId,
) -> None:
    asset_ref = uuid4()
    inventory.seed(asset_ref, tenant_id.value)
    with pytest.raises(ApplicationForbiddenError):
        await container.asset_service.register(
            RegisterAISystemAssetCommand(
                tenant_id=tenant_id.value,
                asset_ref_id=asset_ref,
                discovery_source="ManualRegistration",
                actor_roles=READER,
            )
        )


@pytest.mark.asyncio
async def test_bulk_triage_and_resolve(container: AIPostureContainer, tenant_id: TenantId) -> None:
    for i in range(3):
        await container.alert_service.raise_alert(
            RaiseShadowAIAlertCommand(
                tenant_id=tenant_id.value,
                cloud_account="acct",
                resource_identifier=f"r-{i}",
                service_type="bedrock",
                region="us-east-1",
                discovery_source="ManualRegistration",
                actor_roles=ENGINEER,
            )
        )
    triage = await container.alert_service.bulk_triage(
        BulkTriageShadowAIAlertsCommand(
            tenant_id=tenant_id.value,
            triaged_by="analyst-1",
            service_type="bedrock",
            actor_roles=ANALYST,
        )
    )
    assert triage.triaged_count == 3
    result = await container.alert_service.bulk_resolve(
        BulkResolveShadowAIAlertsCommand(
            tenant_id=tenant_id.value,
            alert_ids=tuple(UUID(x) for x in triage.alert_ids),
            resolution_action="ExemptedByPolicy",
            confirm_as="ConfirmedFalsePositive",
            false_positive_reason="known sandbox",
            actor_roles=APPROVER,
        )
    )
    assert result.triaged_count == 3


@pytest.mark.asyncio
async def test_discovery_only_mode_suppresses_alerts(
    container: AIPostureContainer, tenant_id: TenantId
) -> None:
    await container.alert_service.set_discovery_only_mode(
        SetDiscoveryOnlyModeCommand(tenant_id=tenant_id.value, enabled=True, actor_roles=ADMIN)
    )
    dto = await container.alert_service.raise_alert(
        RaiseShadowAIAlertCommand(
            tenant_id=tenant_id.value,
            cloud_account="acct",
            resource_identifier="hidden",
            service_type="sagemaker",
            region="eu-west-1",
            discovery_source="ManualRegistration",
            actor_roles=ENGINEER,
        )
    )
    assert dto is None


@pytest.mark.asyncio
async def test_triage_backlog_age(container: AIPostureContainer, tenant_id: TenantId) -> None:
    await container.alert_service.raise_alert(
        RaiseShadowAIAlertCommand(
            tenant_id=tenant_id.value,
            cloud_account="acct",
            resource_identifier="r-age",
            service_type="bedrock",
            region="us-east-1",
            discovery_source="ManualRegistration",
            actor_roles=ENGINEER,
        )
    )
    age = await container.alert_service.triage_backlog_age(tenant_id.value)
    assert age.open_total == 1
    assert age.buckets["0-1"] == 1


@pytest.mark.asyncio
async def test_tenant_isolation_on_get(
    container: AIPostureContainer,
    inventory: StubInventoryQueryAdapter,
    tenant_id: TenantId,
    other_tenant_id: TenantId,
) -> None:
    asset_ref = uuid4()
    inventory.seed(asset_ref, tenant_id.value)
    dto = await container.asset_service.register(
        RegisterAISystemAssetCommand(
            tenant_id=tenant_id.value,
            asset_ref_id=asset_ref,
            discovery_source="ManualRegistration",
            actor_roles=ENGINEER,
        )
    )
    from ai_posture.application.exceptions import ApplicationNotFoundError

    with pytest.raises(ApplicationNotFoundError):
        await container.asset_service.get(other_tenant_id.value, UUID(dto.asset_id))
