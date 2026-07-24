from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cloud_security.application.exceptions import DuplicateDiscoveryJobError
from cloud_security.application.registry.in_memory_discovery_job_registry import (
    InMemoryDiscoveryJobRegistry,
)
from cloud_security.domain.aggregates.cloud_discovery_job import CloudDiscoveryJob
from cloud_security.domain.value_objects.discovery_window import DiscoveryWindow
from cloud_security.domain.value_objects.identifiers import (
    AccountId,
    DiscoveryJobId,
    ProviderId,
    TenantId,
)

NOW = datetime.now(UTC)
WINDOW = DiscoveryWindow(start=NOW - timedelta(hours=1), end=NOW)


def _start(tenant_id, account_id=None, provider_id=None, **overrides) -> CloudDiscoveryJob:
    defaults = {
        "job_id": DiscoveryJobId.generate(),
        "tenant_id": tenant_id,
        "account_id": account_id or AccountId.generate(),
        "provider_id": provider_id or ProviderId.generate(),
        "window": WINDOW,
        "now": NOW,
    }
    defaults.update(overrides)
    return CloudDiscoveryJob.start(**defaults)


def test_register_then_get_returns_same_job() -> None:
    registry = InMemoryDiscoveryJobRegistry()
    tenant_id = TenantId.generate()
    job = _start(tenant_id)
    registry.register(job)

    assert registry.get(tenant_id, job.job_id) is job


def test_get_wrong_tenant_returns_none() -> None:
    registry = InMemoryDiscoveryJobRegistry()
    job = _start(TenantId.generate())
    registry.register(job)

    assert registry.get(TenantId.generate(), job.job_id) is None


def test_get_unknown_id_returns_none() -> None:
    registry = InMemoryDiscoveryJobRegistry()
    assert registry.get(TenantId.generate(), DiscoveryJobId.generate()) is None


def test_duplicate_active_job_for_same_account_provider_raises() -> None:
    registry = InMemoryDiscoveryJobRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    provider_id = ProviderId.generate()
    registry.register(_start(tenant_id, account_id, provider_id))

    with pytest.raises(DuplicateDiscoveryJobError):
        registry.register(_start(tenant_id, account_id, provider_id))


def test_different_providers_same_account_do_not_conflict() -> None:
    registry = InMemoryDiscoveryJobRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    registry.register(_start(tenant_id, account_id, ProviderId.generate()))
    registry.register(_start(tenant_id, account_id, ProviderId.generate()))  # no raise


def test_has_active_job() -> None:
    registry = InMemoryDiscoveryJobRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    provider_id = ProviderId.generate()
    registry.register(_start(tenant_id, account_id, provider_id))

    assert registry.has_active_job(tenant_id, account_id, provider_id) is True
    assert registry.has_active_job(tenant_id, account_id, ProviderId.generate()) is False


def test_list_scoped_to_tenant_and_account() -> None:
    registry = InMemoryDiscoveryJobRegistry()
    tenant_a, tenant_b = TenantId.generate(), TenantId.generate()
    account_x = AccountId.generate()
    job_a = _start(tenant_a, account_x)
    job_b = _start(tenant_b)
    registry.register(job_a)
    registry.register(job_b)

    assert registry.list(tenant_a) == (job_a,)
    assert registry.list(tenant_a, account_id=account_x) == (job_a,)
    assert registry.list(tenant_a, account_id=AccountId.generate()) == ()


def test_list_active_only_returns_in_progress() -> None:
    registry = InMemoryDiscoveryJobRegistry()
    tenant_id = TenantId.generate()
    active = _start(tenant_id)
    completed = _start(tenant_id)
    registry.register(active)
    registry.register(completed)
    completed.complete(tenant_id, NOW)

    assert registry.list_active(tenant_id) == (active,)


def test_release_frees_slot_for_new_job() -> None:
    registry = InMemoryDiscoveryJobRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    provider_id = ProviderId.generate()
    job = _start(tenant_id, account_id, provider_id)
    registry.register(job)

    job.complete(tenant_id, NOW)
    registry.release(job)

    assert registry.has_active_job(tenant_id, account_id, provider_id) is False
    registry.register(_start(tenant_id, account_id, provider_id))  # no raise


def test_release_is_noop_while_in_progress() -> None:
    registry = InMemoryDiscoveryJobRegistry()
    tenant_id = TenantId.generate()
    account_id = AccountId.generate()
    provider_id = ProviderId.generate()
    job = _start(tenant_id, account_id, provider_id)
    registry.register(job)

    registry.release(job)  # still IN_PROGRESS, must not free the slot

    assert registry.has_active_job(tenant_id, account_id, provider_id) is True
