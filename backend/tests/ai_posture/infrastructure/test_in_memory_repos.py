"""Repository tests for in-memory ai_posture persistence."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

import pytest

from ai_posture.domain.aggregates.ai_risk_score_snapshot import AIRiskScoreSnapshot
from ai_posture.domain.aggregates.ai_system_asset import AISystemAsset
from ai_posture.domain.aggregates.ai_threat_profile import AIThreatProfile
from ai_posture.domain.aggregates.shadow_ai_alert import ShadowAIAlert
from ai_posture.domain.services.ai_risk_scoring_service import AIRiskScoringService
from ai_posture.domain.value_objects.enums import (
    AIAssetDiscoverySource,
    AISystemKind,
    DataSensitivityClassification,
)
from ai_posture.domain.value_objects.identifiers import (
    AIRiskScoreSnapshotId,
    AISystemAssetId,
    AIThreatProfileId,
    ShadowAIAlertId,
    TenantId,
)
from ai_posture.domain.value_objects.posture_vos import (
    AssetRef,
    DiscoveredServiceFingerprint,
    DiscoverySourceRecord,
)
from ai_posture.infrastructure.persistence.in_memory_unit_of_work import (
    InMemoryUnitOfWork,
)


@pytest.mark.asyncio
async def test_asset_repo_tenant_isolation(
    now: datetime, tenant_id: TenantId, other_tenant_id: TenantId
) -> None:
    uow = InMemoryUnitOfWork()
    asset = AISystemAsset.discover(
        asset_id=AISystemAssetId.generate(),
        tenant_id=tenant_id,
        asset_ref=AssetRef(uuid4()),
        discovery_source=DiscoverySourceRecord(
            AIAssetDiscoverySource.MANUAL_REGISTRATION, now, now
        ),
        data_sensitivity=DataSensitivityClassification.INTERNAL,
        now=now,
    )
    await uow.assets.save(asset)
    assert await uow.assets.find_by_id(asset.asset_id, tenant_id) is not None
    assert await uow.assets.find_by_id(asset.asset_id, other_tenant_id) is None


@pytest.mark.asyncio
async def test_alert_fingerprint_lookup(now: datetime, tenant_id: TenantId) -> None:
    uow = InMemoryUnitOfWork()
    fp = DiscoveredServiceFingerprint(
        cloud_account="a",
        resource_identifier="r",
        service_type="s",
        region="us-east-1",
        discovery_source=AIAssetDiscoverySource.CLOUD_PROVIDER_SCAN,
    )
    alert = ShadowAIAlert.raise_alert(ShadowAIAlertId.generate(), tenant_id, fp, now)
    await uow.alerts.save(alert)
    found = await uow.alerts.find_by_fingerprint(fp, tenant_id)
    assert found is not None
    assert str(found.alert_id) == str(alert.alert_id)


@pytest.mark.asyncio
async def test_profile_find_stale(now: datetime, tenant_id: TenantId) -> None:
    uow = InMemoryUnitOfWork()
    profile = AIThreatProfile.create(
        profile_id=AIThreatProfileId.generate(),
        tenant_id=tenant_id,
        ai_system_asset_id=AISystemAssetId.generate(),
        ai_system_kind=AISystemKind.AI_AGENT,
        now=now,
    )
    await uow.profiles.save(profile)
    stale = await uow.profiles.find_stale(1, tenant_id)
    assert len(stale) == 1


@pytest.mark.asyncio
async def test_snapshot_find_stale_asset_ids(now: datetime, tenant_id: TenantId) -> None:
    uow = InMemoryUnitOfWork()
    scorer = AIRiskScoringService()
    asset_id = AISystemAssetId.generate()
    snap = AIRiskScoreSnapshot.create(
        snapshot_id=AIRiskScoreSnapshotId.generate(),
        tenant_id=tenant_id,
        ai_system_asset_id=asset_id,
        components=scorer.build_components(max_exposure_score=25.0),
        now=now - timedelta(hours=48),
    )
    await uow.snapshots.save(snap)
    stale = await uow.snapshots.find_stale_asset_ids(timedelta(hours=24), tenant_id)
    assert asset_id in stale
