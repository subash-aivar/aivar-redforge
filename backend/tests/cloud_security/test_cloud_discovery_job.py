from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cloud_security.domain.aggregates.cloud_discovery_job import CloudDiscoveryJob
from cloud_security.domain.events.discovery_job_events import (
    DiscoveryJobCancelled,
    DiscoveryJobCompleted,
    DiscoveryJobFailed,
    DiscoveryJobStarted,
)
from cloud_security.domain.exceptions.domain_exceptions import (
    InvalidDiscoveryJobTransition,
    TenantMismatch,
)
from cloud_security.domain.value_objects.discovery_window import DiscoveryWindow
from cloud_security.domain.value_objects.enums import DiscoveryJobStatus
from cloud_security.domain.value_objects.identifiers import (
    AccountId,
    DiscoveryJobId,
    ProviderId,
    TenantId,
)

NOW = datetime.now(UTC)
WINDOW = DiscoveryWindow(start=NOW - timedelta(hours=1), end=NOW)


def _start(**overrides) -> CloudDiscoveryJob:
    defaults = {
        "job_id": DiscoveryJobId.generate(),
        "tenant_id": TenantId.generate(),
        "account_id": AccountId.generate(),
        "provider_id": ProviderId.generate(),
        "window": WINDOW,
        "now": NOW,
    }
    defaults.update(overrides)
    return CloudDiscoveryJob.start(**defaults)


def test_start_is_in_progress_and_emits_event() -> None:
    job = _start()
    assert job.status == DiscoveryJobStatus.IN_PROGRESS
    assert job.discovered_count == 0
    assert job.updated_count == 0
    assert job.failed_count == 0
    assert job.discovered_asset_ids == ()

    events = job.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], DiscoveryJobStarted)

    assert job.pop_events() == []


def test_record_discovered_asset_new_and_updated() -> None:
    job = _start()
    job.record_discovered_asset(job.tenant_id, "asset-1", updated=False)
    job.record_discovered_asset(job.tenant_id, "asset-2", updated=True)

    assert job.discovered_count == 1
    assert job.updated_count == 1
    assert job.discovered_asset_ids == ("asset-1", "asset-2")


def test_record_failure_increments_failed_count() -> None:
    job = _start()
    job.record_failure(job.tenant_id)
    job.record_failure(job.tenant_id)
    assert job.failed_count == 2


def test_complete_emits_event_with_counts() -> None:
    job = _start()
    job.pop_events()
    job.record_discovered_asset(job.tenant_id, "asset-1", updated=False)

    job.complete(job.tenant_id, NOW)

    assert job.status == DiscoveryJobStatus.COMPLETED
    assert job.completed_at == NOW
    events = job.pop_events()
    assert isinstance(events[0], DiscoveryJobCompleted)
    assert events[0].discovered_count == 1


def test_fail_emits_event_with_reason() -> None:
    job = _start()
    job.pop_events()

    job.fail(job.tenant_id, "provider unavailable", NOW)

    assert job.status == DiscoveryJobStatus.FAILED
    assert job.failure_reason == "provider unavailable"
    events = job.pop_events()
    assert isinstance(events[0], DiscoveryJobFailed)


def test_cancel_emits_event() -> None:
    job = _start()
    job.pop_events()

    job.cancel(job.tenant_id, NOW)

    assert job.status == DiscoveryJobStatus.CANCELLED
    assert job.cancelled_at == NOW
    events = job.pop_events()
    assert isinstance(events[0], DiscoveryJobCancelled)


@pytest.mark.parametrize("method_name", ["complete", "fail", "cancel"])
def test_terminal_transition_twice_raises(method_name: str) -> None:
    job = _start()
    job.complete(job.tenant_id, NOW)

    method = getattr(job, method_name)
    with pytest.raises(InvalidDiscoveryJobTransition):
        if method_name == "fail":
            method(job.tenant_id, "x", NOW)
        else:
            method(job.tenant_id, NOW)


def test_record_progress_after_terminal_raises() -> None:
    job = _start()
    job.complete(job.tenant_id, NOW)

    with pytest.raises(InvalidDiscoveryJobTransition):
        job.record_discovered_asset(job.tenant_id, "asset-1", updated=False)
    with pytest.raises(InvalidDiscoveryJobTransition):
        job.record_failure(job.tenant_id)


def test_wrong_tenant_raises_on_every_mutator() -> None:
    job = _start()
    other_tenant = TenantId.generate()

    with pytest.raises(TenantMismatch):
        job.record_discovered_asset(other_tenant, "asset-1", updated=False)
    with pytest.raises(TenantMismatch):
        job.record_failure(other_tenant)
    with pytest.raises(TenantMismatch):
        job.complete(other_tenant, NOW)
    with pytest.raises(TenantMismatch):
        job.fail(other_tenant, "x", NOW)
    with pytest.raises(TenantMismatch):
        job.cancel(other_tenant, NOW)
