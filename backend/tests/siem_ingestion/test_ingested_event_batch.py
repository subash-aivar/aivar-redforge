from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.shared.identifiers import EntityId
from siem_ingestion.domain.aggregates.ingested_event_batch import IngestedEventBatch
from siem_ingestion.domain.events.ingestion_events import (
    EventBatchIngested,
    EventBatchThrottled,
)
from siem_ingestion.domain.exceptions.domain_exceptions import (
    EmptyBatchError,
    InvalidBatchFingerprintError,
    InvalidBatchTransition,
    TenantMismatch,
)
from siem_ingestion.domain.value_objects.enums import BatchStatus, IngestionSourceType
from siem_ingestion.domain.value_objects.identifiers import IngestedEventBatchId
from siem_ingestion.domain.value_objects.source_ref import IngestionSourceRef

NOW = datetime.now(UTC)


def _tenant() -> EntityId:
    return EntityId.generate()


def _source() -> IngestionSourceRef:
    return IngestionSourceRef(source_type=IngestionSourceType.CLOUD, vendor="aws-cloudtrail")


def _receive(tenant_id: EntityId | None = None, event_count: int = 10) -> IngestedEventBatch:
    return IngestedEventBatch.receive(
        batch_id=IngestedEventBatchId.generate(),
        tenant_id=tenant_id or _tenant(),
        source=_source(),
        batch_fingerprint="fp-123",
        event_count=event_count,
        now=NOW,
    )


def test_receive_creates_pending_batch() -> None:
    batch = _receive()
    assert batch.status == BatchStatus.PENDING
    assert batch.pop_events() == []


def test_receive_rejects_empty_batch() -> None:
    with pytest.raises(EmptyBatchError):
        _receive(event_count=0)


def test_receive_rejects_blank_fingerprint() -> None:
    with pytest.raises(InvalidBatchFingerprintError):
        IngestedEventBatch.receive(
            batch_id=IngestedEventBatchId.generate(),
            tenant_id=_tenant(),
            source=_source(),
            batch_fingerprint="   ",
            event_count=5,
            now=NOW,
        )


def test_admit_transitions_to_accepted_and_emits_event() -> None:
    tenant_id = _tenant()
    batch = _receive(tenant_id=tenant_id)
    batch.admit(tenant_id, NOW)

    assert batch.status == BatchStatus.ACCEPTED
    events = batch.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], EventBatchIngested)
    assert events[0].event_count == batch.event_count


def test_admit_pops_events_only_once() -> None:
    tenant_id = _tenant()
    batch = _receive(tenant_id=tenant_id)
    batch.admit(tenant_id, NOW)

    assert len(batch.pop_events()) == 1
    assert batch.pop_events() == []


def test_admit_twice_raises_invalid_transition() -> None:
    tenant_id = _tenant()
    batch = _receive(tenant_id=tenant_id)
    batch.admit(tenant_id, NOW)

    with pytest.raises(InvalidBatchTransition):
        batch.admit(tenant_id, NOW)


def test_admit_wrong_tenant_raises_tenant_mismatch() -> None:
    batch = _receive()
    with pytest.raises(TenantMismatch):
        batch.admit(_tenant(), NOW)


def test_throttle_is_first_class_non_error_outcome() -> None:
    """THROTTLED is not an error path (M37 §3) — it must succeed cleanly
    and produce a domain event, not raise."""
    tenant_id = _tenant()
    batch = _receive(tenant_id=tenant_id)
    batch.throttle(tenant_id, "tenant quota exceeded", NOW)

    assert batch.status == BatchStatus.THROTTLED
    events = batch.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], EventBatchThrottled)
    assert events[0].throttle_reason == "tenant quota exceeded"


def test_throttle_requires_non_empty_reason() -> None:
    tenant_id = _tenant()
    batch = _receive(tenant_id=tenant_id)
    with pytest.raises(ValueError, match="reason"):
        batch.throttle(tenant_id, "  ", NOW)


def test_throttle_after_admit_raises_invalid_transition() -> None:
    tenant_id = _tenant()
    batch = _receive(tenant_id=tenant_id)
    batch.admit(tenant_id, NOW)
    with pytest.raises(InvalidBatchTransition):
        batch.throttle(tenant_id, "too late", NOW)


def test_reject_transitions_to_rejected_without_event() -> None:
    tenant_id = _tenant()
    batch = _receive(tenant_id=tenant_id)
    batch.reject(tenant_id, NOW)

    assert batch.status == BatchStatus.REJECTED
    assert batch.pop_events() == []


def test_connector_source_requires_connector_id() -> None:
    with pytest.raises(ValueError, match="source_connector_id"):
        IngestionSourceRef(source_type=IngestionSourceType.CONNECTOR, vendor="okta")


def test_source_ref_requires_non_empty_vendor() -> None:
    with pytest.raises(ValueError, match="vendor"):
        IngestionSourceRef(source_type=IngestionSourceType.AGENT, vendor="")
