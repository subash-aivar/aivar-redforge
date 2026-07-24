"""Application-layer tests for Phase 2 threat + risk scoring."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from ai_posture.application.commands.posture_commands import (
    AssessThreatProfileCommand,
    ClassifyAISystemAssetCommand,
    ComputeRiskScoreCommand,
    CreateThreatProfileCommand,
    RegisterAISystemAssetCommand,
    RunStalenessSweepCommand,
)
from ai_posture.domain.value_objects.identifiers import TenantId
from ai_posture.infrastructure.acl.degraded_adapters import StubInventoryQueryAdapter
from ai_posture.infrastructure.container import AIPostureContainer
from tests.ai_posture.conftest import ENGINEER


async def _registered_asset(
    container: AIPostureContainer,
    inventory: StubInventoryQueryAdapter,
    tenant_id: TenantId,
) -> UUID:
    asset_ref = uuid4()
    inventory.seed(asset_ref, tenant_id.value)
    dto = await container.asset_service.register(
        RegisterAISystemAssetCommand(
            tenant_id=tenant_id,
            asset_ref_id=asset_ref,
            discovery_source="ManualRegistration",
            actor_roles=ENGINEER,
        )
    )
    asset_id = UUID(dto.asset_id)
    await container.asset_service.classify(
        ClassifyAISystemAssetCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            ai_system_kind="FoundationModelAPI",
            actor_roles=ENGINEER,
        )
    )
    return asset_id


@pytest.mark.asyncio
async def test_create_threat_profile_attaches_ref_only(
    container: AIPostureContainer,
    inventory: StubInventoryQueryAdapter,
    tenant_id: TenantId,
) -> None:
    asset_id = await _registered_asset(container, inventory, tenant_id)
    profile = await container.threat_service.create_profile(
        CreateThreatProfileCommand(
            tenant_id=tenant_id, asset_id=asset_id, actor_roles=ENGINEER
        )
    )
    asset = await container.asset_service.get(tenant_id, asset_id)
    assert asset.threat_profile_id == profile.profile_id
    # Independence: second create is idempotent
    again = await container.threat_service.create_profile(
        CreateThreatProfileCommand(
            tenant_id=tenant_id, asset_id=asset_id, actor_roles=ENGINEER
        )
    )
    assert again.profile_id == profile.profile_id


@pytest.mark.asyncio
async def test_assess_and_compute_risk_score(
    container: AIPostureContainer,
    inventory: StubInventoryQueryAdapter,
    tenant_id: TenantId,
) -> None:
    asset_id = await _registered_asset(container, inventory, tenant_id)
    await container.threat_service.create_profile(
        CreateThreatProfileCommand(
            tenant_id=tenant_id, asset_id=asset_id, actor_roles=ENGINEER
        )
    )
    assessed = await container.threat_service.assess(
        AssessThreatProfileCommand(
            tenant_id=tenant_id,
            asset_id=asset_id,
            evidence_refs=["ev-1"],
            actor_roles=ENGINEER,
        )
    )
    assert assessed.requires_reassessment is False or assessed.max_exposure_level
    snap = await container.risk_service.compute(
        ComputeRiskScoreCommand(tenant_id=tenant_id, asset_id=asset_id, actor_roles=ENGINEER)
    )
    assert 0.0 <= snap.composite_score <= 100.0
    cached = await container.risk_service.get_latest(tenant_id, asset_id)
    assert cached is not None
    assert cached.snapshot_id == snap.snapshot_id


@pytest.mark.asyncio
async def test_get_risk_score_never_computes(
    container: AIPostureContainer,
    inventory: StubInventoryQueryAdapter,
    tenant_id: TenantId,
) -> None:
    asset_id = await _registered_asset(container, inventory, tenant_id)
    assert await container.risk_service.get_latest(tenant_id, asset_id) is None


@pytest.mark.asyncio
async def test_staleness_sweep_flags_unassessed_profiles(
    container: AIPostureContainer,
    inventory: StubInventoryQueryAdapter,
    tenant_id: TenantId,
) -> None:
    asset_id = await _registered_asset(container, inventory, tenant_id)
    await container.threat_service.create_profile(
        CreateThreatProfileCommand(
            tenant_id=tenant_id, asset_id=asset_id, actor_roles=ENGINEER
        )
    )
    result = await container.risk_service.run_staleness_sweep(
        RunStalenessSweepCommand(
            tenant_id=tenant_id,
            threat_threshold_days=1,
            actor_roles=ENGINEER,
        )
    )
    assert result.profiles_flagged >= 1
