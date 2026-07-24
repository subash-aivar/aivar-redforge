"""StorageApplicationService — the Storage Foundation's single
application-layer entrypoint (M42 Phase 5 / M43E).

Orchestrates, in order: authorization, tenant/tier/retention
validation, storage-strategy selection (`IStorageStrategyRegistry`),
plan production, and — only for initial placement, where a full
`CanonicalEvent` is actually on hand — hand-off to
`IEventStorageWriter`. This service never persists anything: it always
stops at producing a `StoragePlan` (or, for a retention-policy request,
at validating and echoing back the accepted policy).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.shared.timestamps import utc_now
from siem_storage.application import _auth
from siem_storage.application.dtos.storage_plan import StoragePlanIntent
from siem_storage.application.dtos.storage_result import (
    BatchStorageResult,
    StorageFailure,
    StorageResult,
    StorageStatus,
)
from siem_storage.application.exceptions import (
    ApplicationValidationError,
    EmptyBatchStorageError,
    InvalidInitialTierError,
    MissingRequiredFieldError,
    RetentionPolicyIncompatibleError,
    TenantContextMismatchError,
    UnsupportedStorageTierError,
)
from siem_storage.application.services.lifecycle_validation import validate_lifecycle_transition
from siem_storage.domain.exceptions.domain_exceptions import SiemStorageDomainError
from siem_storage.domain.value_objects.enums import StorageRole, StorageTier

if TYPE_CHECKING:
    from datetime import datetime

    from redforge.shared.identifiers import EntityId
    from siem_shared.domain.value_objects.canonical_event import CanonicalEvent
    from siem_storage.application.commands.storage_commands import (
        ApplyRetentionPolicyCommand,
        ArchiveEventCommand,
        StoreBatchCommand,
        StoreCanonicalEventCommand,
    )
    from siem_storage.application.ports.i_event_storage_writer import IEventStorageWriter
    from siem_storage.application.ports.i_storage_strategy_registry import (
        IStorageStrategyRegistry,
    )
    from siem_storage.domain.value_objects.retention import RetentionPolicy

_VALIDATION_ERRORS = (ApplicationValidationError, SiemStorageDomainError, ValueError)


def _to_failure(stage: str, exc: Exception) -> StorageFailure:
    return StorageFailure(stage=stage, error_type=type(exc).__name__, message=str(exc))


class StorageApplicationService:
    def __init__(
        self,
        strategy_registry: IStorageStrategyRegistry,
        writer: IEventStorageWriter,
    ) -> None:
        self._registry = strategy_registry
        self._writer = writer

    def store_event(self, cmd: StoreCanonicalEventCommand) -> StorageResult:
        _auth.require_at_least(cmd.actor_roles, StorageRole.PLANNER)
        now = utc_now()
        return self._plan_initial_placement(
            cmd.tenant_id, cmd.canonical_event, cmd.requested_tier, cmd.retention_policy, now
        )

    def store_batch(self, cmd: StoreBatchCommand) -> BatchStorageResult:
        _auth.require_at_least(cmd.actor_roles, StorageRole.PLANNER)
        if not cmd.events:
            raise EmptyBatchStorageError()
        now = utc_now()

        results = tuple(
            self._plan_initial_placement(
                cmd.tenant_id, event, cmd.requested_tier, cmd.retention_policy, now
            )
            for event in cmd.events
        )
        accepted = sum(1 for r in results if r.status == StorageStatus.ACCEPTED)

        if accepted == len(results):
            overall = StorageStatus.ACCEPTED
        elif accepted == 0:
            overall = StorageStatus.REJECTED
        else:
            overall = StorageStatus.PARTIALLY_ACCEPTED

        return BatchStorageResult(status=overall, results=results)

    def archive_event(self, cmd: ArchiveEventCommand) -> StorageResult:
        _auth.require_at_least(cmd.actor_roles, StorageRole.PLANNER)
        now = utc_now()

        try:
            self._validate_archive_request(cmd)
            validate_lifecycle_transition(cmd.current_tier, cmd.target_tier)
        except _VALIDATION_ERRORS as exc:
            return StorageResult(
                status=StorageStatus.REJECTED, failures=(_to_failure("validation", exc),)
            )

        try:
            strategy = self._registry.resolve(cmd.target_tier)
        except UnsupportedStorageTierError as exc:
            return StorageResult(
                status=StorageStatus.UNSUPPORTED_TIER,
                failures=(_to_failure("strategy_selection", exc),),
            )

        intent = (
            StoragePlanIntent.ARCHIVAL
            if cmd.target_tier == StorageTier.ARCHIVE
            else StoragePlanIntent.TIER_TRANSITION
        )
        try:
            plan = strategy.plan(
                tenant_id=cmd.tenant_id,
                event_fingerprint=cmd.event_fingerprint,
                category=cmd.event_category,
                retention_policy=cmd.retention_policy,
                intent=intent,
                now=now,
            )
        except _VALIDATION_ERRORS as exc:
            return StorageResult(
                status=StorageStatus.REJECTED, failures=(_to_failure("planning", exc),)
            )

        return StorageResult(status=StorageStatus.ARCHIVE_PLANNED, plan=plan)

    def apply_retention_policy(self, cmd: ApplyRetentionPolicyCommand) -> StorageResult:
        _auth.require_at_least(cmd.actor_roles, StorageRole.PLANNER)
        try:
            self._validate_retention_policy(cmd.tenant_id, cmd.retention_policy)
        except _VALIDATION_ERRORS as exc:
            return StorageResult(
                status=StorageStatus.REJECTED, failures=(_to_failure("validation", exc),)
            )
        return StorageResult(
            status=StorageStatus.RETENTION_APPLIED, applied_retention_policy=cmd.retention_policy
        )

    def _plan_initial_placement(
        self,
        tenant_id: EntityId,
        event: CanonicalEvent,
        requested_tier: StorageTier,
        retention_policy: RetentionPolicy | None,
        now: datetime,
    ) -> StorageResult:
        try:
            self._validate_store_request(tenant_id, event, requested_tier, retention_policy)
        except _VALIDATION_ERRORS as exc:
            return StorageResult(
                status=StorageStatus.REJECTED, failures=(_to_failure("validation", exc),)
            )

        try:
            strategy = self._registry.resolve(requested_tier)
        except UnsupportedStorageTierError as exc:
            return StorageResult(
                status=StorageStatus.UNSUPPORTED_TIER,
                failures=(_to_failure("strategy_selection", exc),),
            )

        assert retention_policy is not None  # validated above
        try:
            plan = strategy.plan(
                tenant_id=tenant_id,
                event_fingerprint=str(event.identity.fingerprint),
                category=event.category.value,
                retention_policy=retention_policy,
                intent=StoragePlanIntent.INITIAL_PLACEMENT,
                now=now,
            )
        except _VALIDATION_ERRORS as exc:
            return StorageResult(
                status=StorageStatus.REJECTED, failures=(_to_failure("planning", exc),)
            )

        self._writer.write(event, plan)
        return StorageResult(status=StorageStatus.ACCEPTED, plan=plan)

    def _validate_store_request(
        self,
        tenant_id: EntityId,
        event: CanonicalEvent,
        requested_tier: StorageTier,
        retention_policy: RetentionPolicy | None,
    ) -> None:
        if event.tenant.tenant_id != tenant_id:
            raise TenantContextMismatchError(tenant_id, event.tenant.tenant_id)
        if requested_tier != StorageTier.HOT:
            raise InvalidInitialTierError(requested_tier)
        if retention_policy is None:
            raise MissingRequiredFieldError("retention_policy")
        if retention_policy.tenant_id != str(tenant_id):
            raise TenantContextMismatchError(str(tenant_id), retention_policy.tenant_id)

    def _validate_archive_request(self, cmd: ArchiveEventCommand) -> None:
        if not cmd.event_fingerprint.strip():
            raise MissingRequiredFieldError("event_fingerprint")
        if not cmd.event_category.strip():
            raise MissingRequiredFieldError("event_category")
        self._validate_retention_policy(cmd.tenant_id, cmd.retention_policy)

    def _validate_retention_policy(
        self, tenant_id: EntityId, retention_policy: RetentionPolicy
    ) -> None:
        if retention_policy.tenant_id != str(tenant_id):
            raise TenantContextMismatchError(str(tenant_id), retention_policy.tenant_id)
        if not retention_policy.durations_by_category:
            raise RetentionPolicyIncompatibleError(
                "policy defines no category retention durations"
            )
