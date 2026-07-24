"""Pydantic schemas for execution API."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field, model_validator


class TriggerKillSwitchRequest(BaseModel):
    scope: str = Field(min_length=1, max_length=32)
    scope_ref: UUID
    authority_role: str = Field(min_length=1, max_length=128)
    reason: str = Field(min_length=1, max_length=2048)


class ReleaseKillSwitchRequest(BaseModel):
    scope: str = Field(min_length=1, max_length=32)
    scope_ref: UUID
    releasing_role: str = Field(min_length=1, max_length=128)
    countersigning_operator_id: UUID | None = None
    countersigning_role: str | None = Field(default=None, max_length=128)


class ReArmKillSwitchRequest(BaseModel):
    scope: str = Field(min_length=1, max_length=32)
    scope_ref: UUID
    authority_role: str = Field(min_length=1, max_length=128)


class KillSwitchResponse(BaseModel):
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


class JournalEntryResponse(BaseModel):
    entry_id: str
    entry_type: str
    sequence_number: int
    entry_hash: str
    previous_entry_hash: str
    content: str
    occurred_at: str


class JournalResponse(BaseModel):
    journal_id: str
    tenant_id: str
    engagement_id: str
    entry_count: int
    entries: list[JournalEntryResponse]
    version: int
    created_at: str
    updated_at: str


class ChainIntegrityResponse(BaseModel):
    status: str
    journal_id: str
    entry_count: int
    broken_at_sequence: int | None
    detail: str


class AuthorizeAndStartRequest(BaseModel):
    engagement_id: UUID
    operation_id: UUID
    step_id: UUID
    target_id: UUID
    technique_id: str = Field(min_length=1, max_length=256)
    technique_category: str = Field(min_length=1, max_length=128)
    impact_ceiling: str = Field(min_length=1, max_length=32)
    worker_id: UUID | None = None
    action_parameters: dict[str, object] = Field(default_factory=dict)
    rate_limit_max: int = Field(default=10, ge=1)
    rate_limit_window_seconds: int = Field(default=60, ge=1)
    presented_scope_hash: str | None = None
    presented_engagement_version: int | None = None
    network_zone: str | None = None


class AbortAttackActionRequest(BaseModel):
    abort_reason: str = Field(min_length=1, max_length=2048)


class CompleteAttackActionRequest(BaseModel):
    output_hash: str | None = Field(default=None, max_length=64)
    output_storage_ref: str | None = Field(default=None, max_length=512)


class FailAttackActionRequest(BaseModel):
    failure_reason: str = Field(min_length=1, max_length=2048)


class AttackActionResponse(BaseModel):
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


class RegisterWorkerRequest(BaseModel):
    worker_type: str = Field(min_length=1, max_length=64)
    network_zone: str = Field(min_length=1, max_length=128)
    techniques: list[str] = Field(min_length=1)
    trust_level: str = Field(min_length=1, max_length=32)
    signature: str = Field(min_length=1, max_length=4096)


class HeartbeatRequest(BaseModel):
    health_status: str = Field(min_length=1, max_length=32)


class ExecutionWorkerResponse(BaseModel):
    worker_id: str
    tenant_id: str
    worker_type: str
    trust_level: str
    health_status: str
    network_zone: str
    capabilities: list[str]
    manifest_hash: str
    last_heartbeat_at: str | None
    version: int


class DetectionCoverageResponse(BaseModel):
    tenant_id: str
    view_key: str = "default"
    total_actions: int = 0
    detected_count: int = 0
    coverage_pct: float = 0.0
    last_event_id: str | None = None
    projection_version: int = 1
    last_updated_at: str | None = None


class ReplaySimulationRequest(BaseModel):
    journal_id: UUID | None = None
    engagement_id: UUID | None = None

    @model_validator(mode="after")
    def require_one_id(self) -> ReplaySimulationRequest:
        if self.journal_id is None and self.engagement_id is None:
            raise ValueError("Either journal_id or engagement_id is required")
        return self


class ProjectionReplayRequest(BaseModel):
    from_position: int = 0
    tenant_id: str | None = None


class CorrelateDetectionFindingRequest(BaseModel):
    action_id: UUID
    finding_id: UUID
    rule_id: str = Field(min_length=1, max_length=128)
    detected_at: datetime
