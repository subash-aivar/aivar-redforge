from __future__ import annotations

from datetime import UTC, datetime

import pytest

from risk_engine.domain.aggregates.risk_correlation_set import RiskCorrelationSet
from risk_engine.domain.events.correlation_events import RiskCorrelationSetFormed
from risk_engine.domain.exceptions.domain_exceptions import InvalidCorrelationSetError
from risk_engine.domain.value_objects.enums import RiskScale, RiskSignalType
from risk_engine.domain.value_objects.identifiers import CorrelationSetId, TenantId
from risk_engine.domain.value_objects.risk_signal import RiskSignalReference

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _signal(tenant_id: TenantId, source_id: str) -> RiskSignalReference:
    return RiskSignalReference(
        tenant_id=tenant_id,
        source_context="vulnerability_engine",
        source_aggregate_type="AssetVulnerability",
        source_id=source_id,
        signal_type=RiskSignalType.SEVERITY_RATING,
        raw_value=5.0,
        raw_scale=RiskScale.CVSS_0_10,
        observed_at=NOW,
        subject_reference="asset-1",
    )


def test_create_with_two_signals_emits_formed_event(tenant_id: TenantId) -> None:
    refs = (_signal(tenant_id, "a"), _signal(tenant_id, "b"))
    correlation_set = RiskCorrelationSet.create(CorrelationSetId.generate(), tenant_id, refs, NOW)
    assert len(correlation_set.signal_references) == 2
    events = correlation_set.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], RiskCorrelationSetFormed)
    assert events[0].signal_count == 2


def test_create_with_single_signal_rejected(tenant_id: TenantId) -> None:
    refs = (_signal(tenant_id, "a"),)
    with pytest.raises(InvalidCorrelationSetError):
        RiskCorrelationSet.create(CorrelationSetId.generate(), tenant_id, refs, NOW)


def test_create_with_empty_signals_rejected(tenant_id: TenantId) -> None:
    with pytest.raises(InvalidCorrelationSetError):
        RiskCorrelationSet.create(CorrelationSetId.generate(), tenant_id, (), NOW)


def test_create_rejects_mismatched_tenant(tenant_id: TenantId) -> None:
    other = TenantId.generate()
    refs = (_signal(tenant_id, "a"), _signal(other, "b"))
    with pytest.raises(InvalidCorrelationSetError):
        RiskCorrelationSet.create(CorrelationSetId.generate(), tenant_id, refs, NOW)
