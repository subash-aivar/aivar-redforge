from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class DraftEnvelopeRequest(BaseModel):
    asset_id: UUID
    max_data_sensitivity: str = "Internal"
    requires_human_approval_for: list[str] = Field(default_factory=list)


class AddActionRequest(BaseModel):
    category: str
    description: str = ""


class ApproveEnvelopeRequest(BaseModel):
    approver_id: str


class ReviseEnvelopeRequest(BaseModel):
    new_actions: list[list[str]] = Field(default_factory=list)
    remove_human_approval_for: list[str] = Field(default_factory=list)


class SuspendEnvelopeRequest(BaseModel):
    reason: str


class ReportActionRequest(BaseModel):
    asset_id: UUID
    action_category: str
    resource: str
    data_sensitivity: str = "Internal"
    human_approval_present: bool = False
    occurred_at: datetime
    idempotency_key: str


class ReviewDeviationRequest(BaseModel):
    decision: str
    notes: str = ""
    linked_revision_event_id: str = ""
