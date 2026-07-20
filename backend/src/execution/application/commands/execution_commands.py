"""Execution application commands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class TriggerKillSwitch:
    tenant_id: UUID
    scope: str
    scope_ref: UUID
    authority_operator_id: UUID
    authority_role: str
    reason: str


@dataclass(frozen=True, slots=True)
class ReleaseKillSwitch:
    tenant_id: UUID
    scope: str
    scope_ref: UUID
    releasing_operator_id: UUID
    releasing_role: str
    countersigning_operator_id: UUID | None = None
    countersigning_role: str | None = None


@dataclass(frozen=True, slots=True)
class ReArmKillSwitch:
    tenant_id: UUID
    scope: str
    scope_ref: UUID
    authority_operator_id: UUID
    authority_role: str


@dataclass(frozen=True, slots=True)
class CreateJournal:
    tenant_id: UUID
    engagement_id: UUID


@dataclass(frozen=True, slots=True)
class AppendJournalEntry:
    tenant_id: UUID
    engagement_id: UUID
    entry_type: str
    content: str
    attribution_operator_id: UUID | None = None
    system_attribution: str | None = None


@dataclass(frozen=True, slots=True)
class AuthorizeAndStartAttackAction:
    tenant_id: UUID
    engagement_id: UUID
    operation_id: UUID
    step_id: UUID
    target_id: UUID
    technique_id: str
    technique_category: str
    impact_ceiling: str
    operator_id: UUID
    worker_id: UUID | None
    action_parameters: dict[str, object]
    rate_limit_max: int
    rate_limit_window_seconds: int
    presented_scope_hash: str | None = None
    presented_engagement_version: int | None = None
    network_zone: str | None = None
    payload_id: UUID | None = None
    expected_payload_hash: str | None = None


@dataclass(frozen=True, slots=True)
class AbortAttackAction:
    tenant_id: UUID
    action_id: UUID
    abort_reason: str
    authority_operator_id: UUID


@dataclass(frozen=True, slots=True)
class CompleteAttackAction:
    tenant_id: UUID
    action_id: UUID
    output_hash: str | None = None
    output_storage_ref: str | None = None


@dataclass(frozen=True, slots=True)
class FailAttackAction:
    tenant_id: UUID
    action_id: UUID
    failure_reason: str


@dataclass(frozen=True, slots=True)
class RecordActionOutput:
    tenant_id: UUID
    action_id: UUID
    output_hash: str
    output_storage_ref: str


@dataclass(frozen=True, slots=True)
class RegisterExecutionWorker:
    tenant_id: UUID
    worker_type: str
    network_zone: str
    techniques: tuple[str, ...]
    trust_level: str
    signer_operator_id: UUID
    signature: str


@dataclass(frozen=True, slots=True)
class DecommissionExecutionWorker:
    tenant_id: UUID
    worker_id: UUID
    authority_operator_id: UUID


@dataclass(frozen=True, slots=True)
class RecordWorkerHeartbeat:
    tenant_id: UUID
    worker_id: UUID
    health_status: str
