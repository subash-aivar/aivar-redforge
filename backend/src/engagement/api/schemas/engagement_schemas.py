"""API request/response schemas for engagement."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from engagement.application.dtos.engagement_dtos import (
    EngagementDTO,
    TargetAuthorizationDTO,
)


class CreateEngagementRequest(BaseModel):
    name: str = Field(min_length=1, max_length=512)
    classification: str
    owner_id: str = Field(min_length=1, max_length=256)
    required_approver_count: int | None = Field(default=None, ge=1)


class DefineScopeRequest(BaseModel):
    asset_ids: list[UUID] = Field(min_length=1)


class SetRoeRequest(BaseModel):
    allowed_techniques: list[str]
    forbidden_targets: list[str] = Field(default_factory=list)
    rate_limits: dict[str, Any] = Field(default_factory=dict)
    escalation_contacts: list[str] = Field(default_factory=list)


class SignRoeRequest(BaseModel):
    owner_id: str = Field(min_length=1, max_length=256)
    signature: str | None = None


class SetWindowRequest(BaseModel):
    authorized_start: datetime
    authorized_end: datetime
    operational_hours: dict[str, Any] = Field(default_factory=dict)


class GrantApprovalRequest(BaseModel):
    approver_id: str = Field(min_length=1, max_length=256)
    signature: str | None = None


class SuspendEngagementRequest(BaseModel):
    reason: str = Field(min_length=1)
    authority: str = Field(min_length=1, max_length=256)


class ResumeEngagementRequest(BaseModel):
    authority: str = Field(min_length=1, max_length=256)


class CloseEngagementRequest(BaseModel):
    reason: str | None = None


class AddParticipantRequest(BaseModel):
    operator_id: str = Field(min_length=1, max_length=256)
    role: str = Field(min_length=1, max_length=128)


class RemoveParticipantRequest(BaseModel):
    operator_id: str = Field(min_length=1, max_length=256)


class ScopeExpansionRequest(BaseModel):
    asset_ids: list[UUID] = Field(min_length=1)


class GrantTargetAuthorizationRequest(BaseModel):
    engagement_id: UUID
    asset_id: UUID
    technique_ids: list[str] = Field(min_length=1)
    impact_ceiling: str
    max_execution_count: int = Field(ge=1)
    valid_until: datetime
    granted_by: str = Field(min_length=1, max_length=256)
    destruct_approval_granted: bool = False
    phase_id: UUID | None = None


class RevokeTargetAuthorizationRequest(BaseModel):
    reason: str = Field(min_length=1)
    revoked_by: str = Field(min_length=1, max_length=256)


class SuspendTargetAuthorizationRequest(BaseModel):
    reason: str = Field(min_length=1)


class TargetRefResponse(BaseModel):
    asset_id: UUID
    display_name: str | None = None


class ApprovalResponse(BaseModel):
    approval_id: UUID
    approver_id: str
    timestamp: datetime
    signature: str
    approval_scope: str
    revoked: bool


class ParticipantResponse(BaseModel):
    participant_id: UUID
    operator_id: str
    role: str
    added_at: datetime
    removed_at: datetime | None = None


class PhaseResponse(BaseModel):
    phase_id: UUID
    name: str
    description: str | None
    sort_order: int


class EngagementResponse(BaseModel):
    engagement_id: UUID
    tenant_id: UUID
    name: str
    classification: str
    owner_id: str
    state: str
    kill_switch_state: str
    engagement_version: int
    scope_hash: str | None
    row_version: int
    created_at: datetime
    updated_at: datetime
    authorized_start: datetime | None = None
    authorized_end: datetime | None = None
    operational_hours: dict[str, Any] = Field(default_factory=dict)
    objectives_summary: str | None = None
    allowed_techniques: list[str] = Field(default_factory=list)
    targets: list[TargetRefResponse] = Field(default_factory=list)
    approvals: list[ApprovalResponse] = Field(default_factory=list)
    participants: list[ParticipantResponse] = Field(default_factory=list)
    phases: list[PhaseResponse] = Field(default_factory=list)
    required_approver_count: int = 1
    quorum_type: str = "Majority"
    roe_version: int | None = None
    roe_signed: bool = False

    @classmethod
    def from_dto(cls, dto: EngagementDTO) -> EngagementResponse:
        return cls(
            engagement_id=dto.engagement_id,
            tenant_id=dto.tenant_id,
            name=dto.name,
            classification=dto.classification,
            owner_id=dto.owner_id,
            state=dto.state,
            kill_switch_state=dto.kill_switch_state,
            engagement_version=dto.engagement_version,
            scope_hash=dto.scope_hash,
            row_version=dto.row_version,
            created_at=dto.created_at,
            updated_at=dto.updated_at,
            authorized_start=dto.authorized_start,
            authorized_end=dto.authorized_end,
            operational_hours=dto.operational_hours,
            objectives_summary=dto.objectives_summary,
            allowed_techniques=dto.allowed_techniques,
            targets=[
                TargetRefResponse(asset_id=t.asset_id, display_name=t.display_name)
                for t in dto.targets
            ],
            approvals=[
                ApprovalResponse(
                    approval_id=a.approval_id,
                    approver_id=a.approver_id,
                    timestamp=a.timestamp,
                    signature=a.signature,
                    approval_scope=a.approval_scope,
                    revoked=a.revoked,
                )
                for a in dto.approvals
            ],
            participants=[
                ParticipantResponse(
                    participant_id=p.participant_id,
                    operator_id=p.operator_id,
                    role=p.role,
                    added_at=p.added_at,
                    removed_at=p.removed_at,
                )
                for p in dto.participants
            ],
            phases=[
                PhaseResponse(
                    phase_id=ph.phase_id,
                    name=ph.name,
                    description=ph.description,
                    sort_order=ph.sort_order,
                )
                for ph in dto.phases
            ],
            required_approver_count=dto.required_approver_count,
            quorum_type=dto.quorum_type,
            roe_version=dto.roe_version,
            roe_signed=dto.roe_signed,
        )


class TargetAuthorizationResponse(BaseModel):
    authorization_id: UUID
    tenant_id: UUID
    engagement_id: UUID
    asset_id: UUID
    display_name: str | None
    technique_ids: list[str]
    impact_ceiling: str
    max_execution_count: int
    state: str
    granted_by: str
    valid_until: datetime
    destruct_approval_granted: bool
    phase_id: UUID | None
    row_version: int
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_dto(cls, dto: TargetAuthorizationDTO) -> TargetAuthorizationResponse:
        return cls(
            authorization_id=dto.authorization_id,
            tenant_id=dto.tenant_id,
            engagement_id=dto.engagement_id,
            asset_id=dto.asset_id,
            display_name=dto.display_name,
            technique_ids=dto.technique_ids,
            impact_ceiling=dto.impact_ceiling,
            max_execution_count=dto.max_execution_count,
            state=dto.state,
            granted_by=dto.granted_by,
            valid_until=dto.valid_until,
            destruct_approval_granted=dto.destruct_approval_granted,
            phase_id=dto.phase_id,
            row_version=dto.row_version,
            created_at=dto.created_at,
            updated_at=dto.updated_at,
        )


class ListEngagementsResponse(BaseModel):
    items: list[EngagementResponse]


class ListTargetAuthorizationsResponse(BaseModel):
    items: list[TargetAuthorizationResponse]
