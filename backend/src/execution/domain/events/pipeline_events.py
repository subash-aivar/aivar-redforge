"""AttackAction and ExecutionWorker domain events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from execution.domain.events.base import BaseDomainEvent

if TYPE_CHECKING:
    from datetime import datetime

    from execution.domain.value_objects.enums import WorkerHealthStatus, WorkerTrustLevel


@dataclass(frozen=True, slots=True, kw_only=True)
class AttackActionAuthorized(BaseDomainEvent):
    engagement_id: str
    operation_id: str
    step_id: str
    target_id: str
    technique_id: str
    operator_id: str
    action_hash: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AttackActionStarted(BaseDomainEvent):
    engagement_id: str
    operation_id: str
    worker_id: str | None
    execution_timestamp: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class AttackActionCompleted(BaseDomainEvent):
    engagement_id: str
    operation_id: str
    completion_timestamp: datetime
    output_hash: str | None


@dataclass(frozen=True, slots=True, kw_only=True)
class AttackActionFailed(BaseDomainEvent):
    engagement_id: str
    operation_id: str
    failure_reason: str
    completion_timestamp: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class AttackActionAborted(BaseDomainEvent):
    engagement_id: str
    operation_id: str
    abort_reason: str
    authority_ref: str
    completion_timestamp: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class AttackActionTimedOut(BaseDomainEvent):
    engagement_id: str
    operation_id: str
    completion_timestamp: datetime
    max_duration_seconds: int


@dataclass(frozen=True, slots=True, kw_only=True)
class AttackActionTamperDetected(BaseDomainEvent):
    engagement_id: str
    operation_id: str
    expected_hash: str
    actual_hash: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionWorkerRegistered(BaseDomainEvent):
    worker_type: str
    trust_level: WorkerTrustLevel
    network_zone: str
    manifest_hash: str
    signer_operator_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionWorkerHeartbeatReceived(BaseDomainEvent):
    health_status: WorkerHealthStatus
    heartbeat_at: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionWorkerHealthDegraded(BaseDomainEvent):
    previous_status: WorkerHealthStatus
    new_status: WorkerHealthStatus
    heartbeat_at: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionWorkerDecommissioned(BaseDomainEvent):
    authority_ref: str
    decommissioned_at: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionAssigned(BaseDomainEvent):
    action_id: str
    worker_id: str
    technique_id: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ExecutionCompleted(BaseDomainEvent):
    action_id: str
    worker_id: str
    outcome: str
