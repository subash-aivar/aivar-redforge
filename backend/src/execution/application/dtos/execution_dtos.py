"""Execution application DTOs."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class KillSwitchDTO:
    kill_switch_id: str
    tenant_id: str
    scope: str
    scope_ref: str
    armed_state: str
    trigger_authority: str | None
    trigger_reason: str | None
    trigger_hash: str | None
    release_authority: str | None
    version: int
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class JournalEntryDTO:
    entry_id: str
    entry_type: str
    sequence_number: int
    entry_hash: str
    previous_entry_hash: str
    content: str
    occurred_at: str


@dataclass(frozen=True, slots=True)
class JournalDTO:
    journal_id: str
    tenant_id: str
    engagement_id: str
    entry_count: int
    entries: tuple[JournalEntryDTO, ...]
    version: int
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class ChainIntegrityReportDTO:
    status: str
    journal_id: str
    entry_count: int
    broken_at_sequence: int | None
    detail: str


@dataclass(frozen=True, slots=True)
class AttackActionDTO:
    action_id: str
    tenant_id: str
    engagement_id: str
    operation_id: str
    step_id: str
    target_id: str
    technique_id: str
    impact_ceiling: str
    state: str
    action_hash: str
    worker_id: str | None
    operator_id: str
    execution_timestamp: str
    completion_timestamp: str | None
    output_hash: str | None
    version: int


@dataclass(frozen=True, slots=True)
class ExecutionWorkerDTO:
    worker_id: str
    tenant_id: str
    worker_type: str
    trust_level: str
    health_status: str
    network_zone: str
    capabilities: tuple[str, ...]
    manifest_hash: str
    last_heartbeat_at: str | None
    version: int
