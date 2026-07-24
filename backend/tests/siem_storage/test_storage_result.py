from __future__ import annotations

from datetime import UTC, datetime

import pytest

from redforge.shared.identifiers import EntityId
from siem_storage.application.dtos.storage_plan import StoragePlan, StoragePlanIntent
from siem_storage.application.dtos.storage_result import (
    BatchStorageResult,
    StorageFailure,
    StorageResult,
    StorageStatus,
)
from siem_storage.domain.value_objects.enums import StorageTier
from siem_storage.domain.value_objects.retention import RetentionDuration, RetentionPolicy


def _plan() -> StoragePlan:
    return StoragePlan(
        tenant_id=EntityId.generate(),
        event_fingerprint="fp-1",
        category="authentication",
        tier=StorageTier.HOT,
        intent=StoragePlanIntent.INITIAL_PLACEMENT,
        retention_duration=RetentionDuration(days=30),
        compression_intent=False,
        encryption_requirement=True,
        archival_intent=False,
        planned_at=datetime.now(UTC),
    )


def test_accepted_requires_plan() -> None:
    with pytest.raises(ValueError, match="plan"):
        StorageResult(status=StorageStatus.ACCEPTED, plan=None)


def test_rejected_forbids_plan() -> None:
    with pytest.raises(ValueError, match="plan"):
        StorageResult(status=StorageStatus.REJECTED, plan=_plan())


def test_retention_applied_requires_policy() -> None:
    with pytest.raises(ValueError, match="applied_retention_policy"):
        StorageResult(status=StorageStatus.RETENTION_APPLIED, applied_retention_policy=None)


def test_accepted_forbids_retention_policy() -> None:
    policy = RetentionPolicy(tenant_id="t-1")
    with pytest.raises(ValueError, match="applied_retention_policy"):
        StorageResult(
            status=StorageStatus.ACCEPTED, plan=_plan(), applied_retention_policy=policy
        )


def test_archive_planned_requires_plan() -> None:
    with pytest.raises(ValueError, match="plan"):
        StorageResult(status=StorageStatus.ARCHIVE_PLANNED, plan=None)


def test_valid_accepted_result() -> None:
    plan = _plan()
    result = StorageResult(status=StorageStatus.ACCEPTED, plan=plan)
    assert result.plan is plan


def test_valid_retention_applied_result() -> None:
    policy = RetentionPolicy(tenant_id="t-1")
    result = StorageResult(status=StorageStatus.RETENTION_APPLIED, applied_retention_policy=policy)
    assert result.applied_retention_policy is policy


def test_batch_result_counts() -> None:
    accepted = StorageResult(status=StorageStatus.ACCEPTED, plan=_plan())
    rejected = StorageResult(
        status=StorageStatus.REJECTED,
        failures=(StorageFailure(stage="x", error_type="Y", message="z"),),
    )
    batch = BatchStorageResult(
        status=StorageStatus.PARTIALLY_ACCEPTED, results=(accepted, rejected)
    )

    assert batch.accepted_count == 1
    assert batch.rejected_count == 1
    assert batch.accepted_plans == (accepted.plan,)


def test_batch_result_defaults_to_empty() -> None:
    batch = BatchStorageResult(status=StorageStatus.REJECTED)
    assert batch.results == ()
    assert batch.accepted_count == 0
    assert batch.accepted_plans == ()
