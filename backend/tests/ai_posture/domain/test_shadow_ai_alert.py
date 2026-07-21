"""Domain tests for ShadowAIAlert aggregate."""

from __future__ import annotations

from datetime import datetime

import pytest

from ai_posture.domain.aggregates.shadow_ai_alert import ShadowAIAlert
from ai_posture.domain.exceptions.domain_exceptions import (
    FalsePositiveReasonRequired,
    InvalidAlertTransition,
)
from ai_posture.domain.value_objects.enums import (
    AIAssetDiscoverySource,
    AlertState,
    ResolutionAction,
)
from ai_posture.domain.value_objects.identifiers import ShadowAIAlertId, TenantId
from ai_posture.domain.value_objects.posture_vos import DiscoveredServiceFingerprint


def _fp() -> DiscoveredServiceFingerprint:
    return DiscoveredServiceFingerprint(
        cloud_account="acct-1",
        resource_identifier="res-1",
        service_type="bedrock",
        region="us-east-1",
        discovery_source=AIAssetDiscoverySource.MANUAL_REGISTRATION,
    )


def test_raise_and_triage(now: datetime, tenant_id: TenantId) -> None:
    alert = ShadowAIAlert.raise_alert(ShadowAIAlertId.generate(), tenant_id, _fp(), now)
    assert alert.state == AlertState.OPEN
    alert.begin_triage(tenant_id, "analyst-1", "looking", now)
    assert alert.state.value == AlertState.UNDER_TRIAGE.value


def test_cannot_triage_twice(now: datetime, tenant_id: TenantId) -> None:
    alert = ShadowAIAlert.raise_alert(ShadowAIAlertId.generate(), tenant_id, _fp(), now)
    alert.begin_triage(tenant_id, "a", "", now)
    with pytest.raises(InvalidAlertTransition):
        alert.begin_triage(tenant_id, "a", "", now)


def test_false_positive_requires_reason(now: datetime, tenant_id: TenantId) -> None:
    alert = ShadowAIAlert.raise_alert(ShadowAIAlertId.generate(), tenant_id, _fp(), now)
    alert.begin_triage(tenant_id, "a", "", now)
    with pytest.raises(FalsePositiveReasonRequired):
        alert.confirm_false_positive(tenant_id, "  ", now)


def test_confirm_and_resolve(now: datetime, tenant_id: TenantId) -> None:
    alert = ShadowAIAlert.raise_alert(ShadowAIAlertId.generate(), tenant_id, _fp(), now)
    alert.begin_triage(tenant_id, "a", "", now)
    alert.confirm_shadow_ai(tenant_id, now)
    alert.resolve(tenant_id, ResolutionAction.REGISTERED_AS_ASSET, None, now)
    assert alert.state == AlertState.RESOLVED


def test_fingerprint_deterministic() -> None:
    a = _fp()
    b = DiscoveredServiceFingerprint(
        cloud_account="ACCT-1",
        resource_identifier="RES-1",
        service_type="Bedrock",
        region="US-EAST-1",
        discovery_source=AIAssetDiscoverySource.MANUAL_REGISTRATION,
    )
    assert a.fingerprint_hash() == b.fingerprint_hash()
