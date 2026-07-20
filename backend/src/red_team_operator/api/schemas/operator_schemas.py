"""Pydantic schemas for RedTeamOperator APIs."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from red_team_operator.application.dtos.operator_dtos import OperatorDTO


class ActivateOperatorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    identity_ref: str = Field(min_length=1, max_length=256)
    clearance_level: str
    display_name: str | None = Field(default=None, max_length=256)
    certifications: list[str] = Field(default_factory=list)
    approval_scopes: list[str] = Field(default_factory=list)
    operator_id: UUID | None = None


class SuspendOperatorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=1024)
    authority: str = Field(min_length=1, max_length=256)


class RevokeOperatorRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=1024)
    authority: str = Field(min_length=1, max_length=256)


class ChangeClearanceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_level: str
    authority: str = Field(min_length=1, max_length=256)


class AddToEngagementRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    engagement_id: UUID


class GrantApprovalAuthorityRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: str


class OperatorResponse(BaseModel):
    operator_id: UUID
    tenant_id: UUID
    identity_ref: str
    display_name: str
    clearance_level: str
    max_impact_ceiling: str
    state: str
    certifications: list[str]
    approval_scopes: list[str]
    active_engagement_ids: list[UUID]
    status_reason: str | None
    status_authority: str | None
    created_at: datetime
    updated_at: datetime
    version: int

    @classmethod
    def from_dto(cls, dto: OperatorDTO) -> OperatorResponse:
        return cls(
            operator_id=dto.operator_id,
            tenant_id=dto.tenant_id,
            identity_ref=dto.identity_ref,
            display_name=dto.display_name,
            clearance_level=dto.clearance_level,
            max_impact_ceiling=dto.max_impact_ceiling,
            state=dto.state,
            certifications=list(dto.certifications),
            approval_scopes=list(dto.approval_scopes),
            active_engagement_ids=list(dto.active_engagement_ids),
            status_reason=dto.status_reason,
            status_authority=dto.status_authority,
            created_at=dto.created_at,
            updated_at=dto.updated_at,
            version=dto.version,
        )


class ListOperatorsResponse(BaseModel):
    items: list[OperatorResponse]
    total: int
    limit: int
    offset: int
