"""Domain exceptions for the execution bounded context."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from execution.domain.value_objects.identifiers import (
        AttackActionId,
        EngagementId,
        ExecutionJournalId,
        ExecutionWorkerId,
        KillSwitchId,
        TenantId,
    )


class DomainException(Exception):
    """Base for all execution domain exceptions."""


class InvalidArgument(DomainException):
    def __init__(self, field: str, reason: str) -> None:
        self.field = field
        self.reason = reason
        super().__init__(f"Invalid argument '{field}': {reason}")


class InvalidStateTransition(DomainException):
    def __init__(self, current: str, attempted: str, aggregate_id: str | None = None) -> None:
        self.current = current
        self.attempted = attempted
        self.aggregate_id = aggregate_id
        detail = f"Invalid state transition from {current} via {attempted}"
        if aggregate_id is not None:
            detail = f"{detail} (id={aggregate_id})"
        super().__init__(detail)


class TenantMismatch(DomainException):
    def __init__(self, expected: TenantId, actual: TenantId) -> None:
        self.expected = expected
        self.actual = actual
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class OptimisticLockConflict(DomainException):
    def __init__(self, aggregate_id: str, expected: int, actual: int) -> None:
        self.aggregate_id = aggregate_id
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Optimistic lock conflict for {aggregate_id}: "
            f"expected version {expected}, actual {actual}"
        )


class KillSwitchNotFound(DomainException):
    def __init__(self, kill_switch_id: KillSwitchId, tenant_id: TenantId) -> None:
        self.kill_switch_id = kill_switch_id
        self.tenant_id = tenant_id
        super().__init__(f"KillSwitch not found: {kill_switch_id} for tenant {tenant_id}")


class JournalNotFound(DomainException):
    def __init__(self, journal_id: ExecutionJournalId, tenant_id: TenantId) -> None:
        self.journal_id = journal_id
        self.tenant_id = tenant_id
        super().__init__(f"ExecutionJournal not found: {journal_id} for tenant {tenant_id}")


class AttackActionNotFound(DomainException):
    def __init__(self, action_id: AttackActionId, tenant_id: TenantId) -> None:
        self.action_id = action_id
        self.tenant_id = tenant_id
        super().__init__(f"AttackAction not found: {action_id} for tenant {tenant_id}")


class ExecutionWorkerNotFound(DomainException):
    def __init__(self, worker_id: ExecutionWorkerId, tenant_id: TenantId) -> None:
        self.worker_id = worker_id
        self.tenant_id = tenant_id
        super().__init__(f"ExecutionWorker not found: {worker_id} for tenant {tenant_id}")


class SameOperatorReleaseForbidden(DomainException):
    def __init__(self, operator_id: str) -> None:
        self.operator_id = operator_id
        super().__init__(
            f"Kill switch cannot be released by the same operator who triggered it: "
            f"{operator_id}"
        )


class PlatformWideReleaseAuthorizationInsufficient(DomainException):
    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(f"Platform-wide kill switch release rejected: {reason}")


class AggregateSealed(DomainException):
    def __init__(self, aggregate_id: str, state: str) -> None:
        self.aggregate_id = aggregate_id
        self.state = state
        super().__init__(f"Aggregate {aggregate_id} is sealed in state {state}")


class AuthorizationRequired(DomainException):
    def __init__(self, reason: str = "AttackAction requires AuthorizationToken") -> None:
        self.reason = reason
        super().__init__(reason)


class AuthorizationDenied(DomainException):
    def __init__(self, reason: str, check: str) -> None:
        self.reason = reason
        self.check = check
        super().__init__(f"Execution authorization denied at {check}: {reason}")


class AttackActionTamperDetected(DomainException):
    def __init__(self, action_id: AttackActionId) -> None:
        self.action_id = action_id
        super().__init__(f"AttackAction tamper detected: {action_id}")


class WorkerCapabilityInsufficient(DomainException):
    def __init__(self, worker_id: str, technique_id: str) -> None:
        self.worker_id = worker_id
        self.technique_id = technique_id
        super().__init__(
            f"Worker {worker_id} lacks capability for technique {technique_id}"
        )


class WorkerTrustInsufficient(DomainException):
    def __init__(self, worker_id: str, trust: str, impact: str) -> None:
        self.worker_id = worker_id
        self.trust = trust
        self.impact = impact
        super().__init__(
            f"Worker {worker_id} trust {trust} insufficient for impact {impact}"
        )


class WorkerDecommissioned(DomainException):
    def __init__(self, worker_id: str) -> None:
        self.worker_id = worker_id
        super().__init__(f"Worker {worker_id} is decommissioned")


class JournalAlreadyExists(DomainException):
    def __init__(self, engagement_id: EngagementId) -> None:
        self.engagement_id = engagement_id
        super().__init__(f"ExecutionJournal already exists for engagement {engagement_id}")


class SignedManifestRequired(DomainException):
    def __init__(self) -> None:
        super().__init__(
            "Worker registration requires a signed capability manifest from redteam:admin"
        )
