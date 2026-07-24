from __future__ import annotations

import dataclasses

import pytest

from redforge.shared.identifiers import EntityId
from siem_storage.application.commands.storage_commands import (
    ApplyRetentionPolicyCommand,
    ArchiveEventCommand,
    StoreBatchCommand,
    StoreCanonicalEventCommand,
)
from siem_storage.application.dtos.storage_result import StorageStatus
from siem_storage.application.exceptions import ApplicationForbiddenError, EmptyBatchStorageError
from siem_storage.application.registry.in_memory_storage_strategy_registry import (
    InMemoryStorageStrategyRegistry,
)
from siem_storage.application.services.storage_application_service import (
    StorageApplicationService,
)
from siem_storage.domain.value_objects.enums import StorageTier
from siem_storage.domain.value_objects.retention import RetentionPolicy

from .conftest import (
    PLANNER_ROLES,
    FakeStorageStrategy,
    make_canonical_event,
    make_retention_policy,
)


def _registry_with_all_tiers() -> InMemoryStorageStrategyRegistry:
    registry = InMemoryStorageStrategyRegistry()
    for tier in StorageTier:
        registry.register(FakeStorageStrategy(tier))
    return registry


def _service(writer, registry=None):
    return StorageApplicationService(
        strategy_registry=registry or _registry_with_all_tiers(), writer=writer
    )


# ---------------------------------------------------------------------------
# store_event — happy path
# ---------------------------------------------------------------------------


def test_store_event_accepted_produces_plan_and_calls_writer(writer):
    tenant_id = EntityId.generate()
    event = make_canonical_event(tenant_id=tenant_id)
    policy = make_retention_policy(tenant_id)
    service = _service(writer)

    result = service.store_event(
        StoreCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=event,
            retention_policy=policy,
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.ACCEPTED
    assert result.plan is not None
    assert result.plan.tier == StorageTier.HOT
    assert writer.written == [(event, result.plan)]


def test_store_event_without_planner_role_raises_forbidden(writer):
    tenant_id = EntityId.generate()
    event = make_canonical_event(tenant_id=tenant_id)
    service = _service(writer)

    with pytest.raises(ApplicationForbiddenError):
        service.store_event(
            StoreCanonicalEventCommand(
                tenant_id=tenant_id,
                canonical_event=event,
                retention_policy=make_retention_policy(tenant_id),
                actor_roles=(),
            )
        )


# ---------------------------------------------------------------------------
# store_event — validation
# ---------------------------------------------------------------------------


def test_store_event_tenant_mismatch_is_rejected(writer):
    tenant_id = EntityId.generate()
    other_tenant_event = make_canonical_event(tenant_id=EntityId.generate())
    service = _service(writer)

    result = service.store_event(
        StoreCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=other_tenant_event,
            retention_policy=make_retention_policy(tenant_id),
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.REJECTED
    assert result.failures[0].error_type == "TenantContextMismatchError"
    assert writer.written == []


def test_store_event_non_hot_initial_tier_is_rejected(writer):
    tenant_id = EntityId.generate()
    event = make_canonical_event(tenant_id=tenant_id)
    service = _service(writer)

    result = service.store_event(
        StoreCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=event,
            requested_tier=StorageTier.WARM,
            retention_policy=make_retention_policy(tenant_id),
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.REJECTED
    assert result.failures[0].error_type == "InvalidInitialTierError"


def test_store_event_missing_retention_policy_is_rejected(writer):
    tenant_id = EntityId.generate()
    event = make_canonical_event(tenant_id=tenant_id)
    service = _service(writer)

    result = service.store_event(
        StoreCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=event,
            retention_policy=None,
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.REJECTED
    assert result.failures[0].error_type == "MissingRequiredFieldError"


def test_store_event_retention_policy_tenant_mismatch_is_rejected(writer):
    tenant_id = EntityId.generate()
    event = make_canonical_event(tenant_id=tenant_id)
    wrong_policy = make_retention_policy(EntityId.generate())
    service = _service(writer)

    result = service.store_event(
        StoreCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=event,
            retention_policy=wrong_policy,
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.REJECTED
    assert result.failures[0].error_type == "TenantContextMismatchError"


def test_store_event_unknown_category_in_policy_is_rejected(writer):
    tenant_id = EntityId.generate()
    event = make_canonical_event(tenant_id=tenant_id)
    policy = make_retention_policy(tenant_id, category="network")  # event category is auth
    service = _service(writer)

    result = service.store_event(
        StoreCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=event,
            retention_policy=policy,
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.REJECTED
    assert result.failures[0].error_type == "UnknownCategoryError"
    assert writer.written == []


def test_store_event_unsupported_tier(writer):
    tenant_id = EntityId.generate()
    event = make_canonical_event(tenant_id=tenant_id)
    empty_registry = InMemoryStorageStrategyRegistry()
    service = _service(writer, empty_registry)

    result = service.store_event(
        StoreCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=event,
            retention_policy=make_retention_policy(tenant_id),
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.UNSUPPORTED_TIER


# ---------------------------------------------------------------------------
# store_batch
# ---------------------------------------------------------------------------


def test_store_batch_all_accepted(writer):
    tenant_id = EntityId.generate()
    events = tuple(make_canonical_event(tenant_id=tenant_id) for _ in range(3))
    service = _service(writer)

    result = service.store_batch(
        StoreBatchCommand(
            tenant_id=tenant_id,
            events=events,
            retention_policy=make_retention_policy(tenant_id),
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.ACCEPTED
    assert result.accepted_count == 3
    assert len(result.accepted_plans) == 3
    assert len(writer.written) == 3


def test_store_batch_partial_acceptance(writer):
    tenant_id = EntityId.generate()
    other_tenant_event = make_canonical_event(tenant_id=EntityId.generate())
    events = (
        make_canonical_event(tenant_id=tenant_id),
        other_tenant_event,
        make_canonical_event(tenant_id=tenant_id),
    )
    service = _service(writer)

    result = service.store_batch(
        StoreBatchCommand(
            tenant_id=tenant_id,
            events=events,
            retention_policy=make_retention_policy(tenant_id),
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.PARTIALLY_ACCEPTED
    assert result.accepted_count == 2
    assert result.rejected_count == 1


def test_store_batch_empty_raises(writer):
    service = _service(writer)
    with pytest.raises(EmptyBatchStorageError):
        service.store_batch(
            StoreBatchCommand(
                tenant_id=EntityId.generate(),
                events=(),
                retention_policy=None,
                actor_roles=PLANNER_ROLES,
            )
        )


# ---------------------------------------------------------------------------
# archive_event
# ---------------------------------------------------------------------------


def test_archive_event_cold_to_archive_is_planned(writer):
    tenant_id = EntityId.generate()
    service = _service(writer)

    result = service.archive_event(
        ArchiveEventCommand(
            tenant_id=tenant_id,
            event_fingerprint="fp-1",
            event_category="authentication",
            current_tier=StorageTier.COLD,
            target_tier=StorageTier.ARCHIVE,
            retention_policy=make_retention_policy(tenant_id),
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.ARCHIVE_PLANNED
    assert result.plan.tier == StorageTier.ARCHIVE
    assert result.plan.archival_intent is True


def test_archive_event_hot_to_warm_is_a_tier_transition_plan(writer):
    tenant_id = EntityId.generate()
    service = _service(writer)

    result = service.archive_event(
        ArchiveEventCommand(
            tenant_id=tenant_id,
            event_fingerprint="fp-1",
            event_category="authentication",
            current_tier=StorageTier.HOT,
            target_tier=StorageTier.WARM,
            retention_policy=make_retention_policy(tenant_id),
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.ARCHIVE_PLANNED
    assert result.plan.tier == StorageTier.WARM


def test_archive_event_invalid_skip_transition_is_rejected(writer):
    tenant_id = EntityId.generate()
    service = _service(writer)

    result = service.archive_event(
        ArchiveEventCommand(
            tenant_id=tenant_id,
            event_fingerprint="fp-1",
            event_category="authentication",
            current_tier=StorageTier.HOT,
            target_tier=StorageTier.COLD,
            retention_policy=make_retention_policy(tenant_id),
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.REJECTED
    assert result.failures[0].error_type == "InvalidLifecycleTransitionError"


def test_archive_event_from_terminal_archive_is_rejected(writer):
    tenant_id = EntityId.generate()
    service = _service(writer)

    result = service.archive_event(
        ArchiveEventCommand(
            tenant_id=tenant_id,
            event_fingerprint="fp-1",
            event_category="authentication",
            current_tier=StorageTier.ARCHIVE,
            target_tier=StorageTier.HOT,
            retention_policy=make_retention_policy(tenant_id),
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.REJECTED


def test_archive_event_blank_fingerprint_is_rejected(writer):
    tenant_id = EntityId.generate()
    service = _service(writer)

    result = service.archive_event(
        ArchiveEventCommand(
            tenant_id=tenant_id,
            event_fingerprint="   ",
            event_category="authentication",
            current_tier=StorageTier.COLD,
            target_tier=StorageTier.ARCHIVE,
            retention_policy=make_retention_policy(tenant_id),
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.REJECTED
    assert result.failures[0].error_type == "MissingRequiredFieldError"


def test_archive_event_unsupported_target_tier(writer):
    tenant_id = EntityId.generate()
    registry = InMemoryStorageStrategyRegistry()
    registry.register(FakeStorageStrategy(StorageTier.COLD))
    service = _service(writer, registry)

    result = service.archive_event(
        ArchiveEventCommand(
            tenant_id=tenant_id,
            event_fingerprint="fp-1",
            event_category="authentication",
            current_tier=StorageTier.COLD,
            target_tier=StorageTier.ARCHIVE,
            retention_policy=make_retention_policy(tenant_id),
            actor_roles=PLANNER_ROLES,
        )
    )

    assert result.status == StorageStatus.UNSUPPORTED_TIER


# ---------------------------------------------------------------------------
# apply_retention_policy
# ---------------------------------------------------------------------------


def test_apply_retention_policy_accepted(writer):
    tenant_id = EntityId.generate()
    policy = make_retention_policy(tenant_id)
    service = _service(writer)

    result = service.apply_retention_policy(
        ApplyRetentionPolicyCommand(
            tenant_id=tenant_id, retention_policy=policy, actor_roles=PLANNER_ROLES
        )
    )

    assert result.status == StorageStatus.RETENTION_APPLIED
    assert result.applied_retention_policy is policy


def test_apply_retention_policy_tenant_mismatch_is_rejected(writer):
    tenant_id = EntityId.generate()
    wrong_policy = make_retention_policy(EntityId.generate())
    service = _service(writer)

    result = service.apply_retention_policy(
        ApplyRetentionPolicyCommand(
            tenant_id=tenant_id, retention_policy=wrong_policy, actor_roles=PLANNER_ROLES
        )
    )

    assert result.status == StorageStatus.REJECTED
    assert result.failures[0].error_type == "TenantContextMismatchError"


def test_apply_retention_policy_with_no_categories_is_rejected(writer):
    tenant_id = EntityId.generate()
    empty_policy = RetentionPolicy(tenant_id=str(tenant_id))
    service = _service(writer)

    result = service.apply_retention_policy(
        ApplyRetentionPolicyCommand(
            tenant_id=tenant_id, retention_policy=empty_policy, actor_roles=PLANNER_ROLES
        )
    )

    assert result.status == StorageStatus.REJECTED
    assert result.failures[0].error_type == "RetentionPolicyIncompatibleError"


def test_apply_retention_policy_without_role_raises_forbidden(writer):
    tenant_id = EntityId.generate()
    service = _service(writer)

    with pytest.raises(ApplicationForbiddenError):
        service.apply_retention_policy(
            ApplyRetentionPolicyCommand(
                tenant_id=tenant_id,
                retention_policy=make_retention_policy(tenant_id),
                actor_roles=(),
            )
        )


# ---------------------------------------------------------------------------
# immutability
# ---------------------------------------------------------------------------


def test_storage_result_is_frozen(writer):
    tenant_id = EntityId.generate()
    service = _service(writer)
    result = service.store_event(
        StoreCanonicalEventCommand(
            tenant_id=tenant_id,
            canonical_event=make_canonical_event(tenant_id=tenant_id),
            retention_policy=make_retention_policy(tenant_id),
            actor_roles=PLANNER_ROLES,
        )
    )
    with pytest.raises(dataclasses.FrozenInstanceError):
        result.status = StorageStatus.REJECTED  # type: ignore[misc]
