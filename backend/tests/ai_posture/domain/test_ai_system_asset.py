"""Domain tests for AISystemAsset aggregate."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

import pytest

from ai_posture.domain.aggregates.ai_system_asset import AISystemAsset
from ai_posture.domain.exceptions.domain_exceptions import (
    AggregateSealed,
    InvalidLifecycleTransition,
    OwnerRequiredForRegistration,
    ShadowAIBlocksRegistration,
    TenantMismatch,
)
from ai_posture.domain.value_objects.enums import (
    AIAssetDiscoverySource,
    AISystemKind,
    AISystemLifecycleState,
    DataSensitivityClassification,
    RegistrationStatus,
)
from ai_posture.domain.value_objects.identifiers import (
    AISystemAssetId,
    AIThreatProfileId,
    TenantId,
)
from ai_posture.domain.value_objects.posture_vos import (
    AIThreatProfileRef,
    AssetRef,
    BusinessOwnerRef,
    DiscoverySourceRecord,
)


def _discover(tenant: TenantId, now: datetime, *, as_shadow: bool = False) -> AISystemAsset:
    return AISystemAsset.discover(
        asset_id=AISystemAssetId.generate(),
        tenant_id=tenant,
        asset_ref=AssetRef(uuid4()),
        discovery_source=DiscoverySourceRecord(
            AIAssetDiscoverySource.MANUAL_REGISTRATION, now, now
        ),
        data_sensitivity=DataSensitivityClassification.INTERNAL,
        now=now,
        as_shadow=as_shadow,
    )


def test_discover_emits_event_and_holds_null_threat_profile_ref(
    now: datetime, tenant_id: TenantId
) -> None:
    asset = _discover(tenant_id, now)
    assert asset.lifecycle_state == AISystemLifecycleState.DISCOVERED
    assert asset.threat_profile_ref is None
    events = asset.pop_events()
    assert any(e.__class__.__name__ == "AISystemAssetDiscovered" for e in events)


def test_classify_moves_to_under_review(now: datetime, tenant_id: TenantId) -> None:
    asset = _discover(tenant_id, now)
    asset.mark_pending_classification(tenant_id, now)
    asset.classify(tenant_id, AISystemKind.FOUNDATION_MODEL_API, now)
    assert asset.lifecycle_state == AISystemLifecycleState.UNDER_REVIEW
    assert asset.ai_system_kind == AISystemKind.FOUNDATION_MODEL_API


def test_approve_requires_owner(now: datetime, tenant_id: TenantId) -> None:
    asset = _discover(tenant_id, now)
    asset.mark_pending_classification(tenant_id, now)
    asset.classify(tenant_id, AISystemKind.RAG_PIPELINE, now)
    with pytest.raises(OwnerRequiredForRegistration):
        asset.approve_registration(tenant_id, now)


def test_shadow_blocks_registration(now: datetime, tenant_id: TenantId) -> None:
    asset = _discover(tenant_id, now, as_shadow=True)
    asset.mark_pending_classification(tenant_id, now)
    asset.classify(tenant_id, AISystemKind.AI_AGENT, now)
    asset.assign_owner(tenant_id, BusinessOwnerRef("o1", "Owner"), now)
    with pytest.raises(ShadowAIBlocksRegistration):
        asset.approve_registration(tenant_id, now)


def test_full_happy_path_to_registered(now: datetime, tenant_id: TenantId) -> None:
    asset = _discover(tenant_id, now)
    asset.mark_pending_classification(tenant_id, now)
    asset.classify(tenant_id, AISystemKind.EMBEDDING_SERVICE, now)
    asset.assign_owner(tenant_id, BusinessOwnerRef("o1"), now)
    asset.approve_registration(tenant_id, now)
    assert asset.lifecycle_state == AISystemLifecycleState.REGISTERED
    assert asset.registration_status == RegistrationStatus.FORMALLY_REGISTERED


def test_decommission_seals_aggregate(now: datetime, tenant_id: TenantId) -> None:
    asset = _discover(tenant_id, now)
    asset.mark_pending_classification(tenant_id, now)
    asset.classify(tenant_id, AISystemKind.VECTOR_STORE, now)
    asset.assign_owner(tenant_id, BusinessOwnerRef("o1"), now)
    asset.approve_registration(tenant_id, now)
    asset.decommission(tenant_id, "retire", now)
    with pytest.raises(AggregateSealed):
        asset.assign_owner(tenant_id, BusinessOwnerRef("o2"), now)


def test_tenant_mismatch(now: datetime, tenant_id: TenantId, other_tenant_id: TenantId) -> None:
    asset = _discover(tenant_id, now)
    with pytest.raises(TenantMismatch):
        asset.classify(other_tenant_id, AISystemKind.MCP_SERVER, now)


def test_attach_threat_profile_ref_only(now: datetime, tenant_id: TenantId) -> None:
    asset = _discover(tenant_id, now)
    asset.mark_pending_classification(tenant_id, now)
    asset.classify(tenant_id, AISystemKind.FOUNDATION_MODEL_API, now)
    ref = AIThreatProfileRef(AIThreatProfileId.generate())
    asset.attach_threat_profile_ref(tenant_id, ref, now)
    assert asset.threat_profile_ref == ref
    # Aggregate holds VO only — no nested threat profile entity
    assert not hasattr(asset, "threat_profile")


def test_invalid_transition_from_discovered_to_registered(
    now: datetime, tenant_id: TenantId
) -> None:
    asset = _discover(tenant_id, now)
    with pytest.raises(InvalidLifecycleTransition):
        asset._transition(AISystemLifecycleState.REGISTERED)
