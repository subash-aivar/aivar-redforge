"""Policy API schemas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class CreateRotationPolicyRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    name: str
    interval_days: int | None
    max_versions_kept: int
    notify_days_before: int
    auto_rotate: bool
    auto_commit: bool = True
    commit_window_hours: int = 24


class UpdateRotationPolicyRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    interval_days: int | None
    max_versions_kept: int
    notify_days_before: int
    auto_rotate: bool
    auto_commit: bool = True
    commit_window_hours: int = 24


class RotationPolicyResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    policy_id: UUID
    tenant_id: str
    name: str
    interval_days: int | None
    max_versions_kept: int
    notify_days_before: int
    auto_rotate: bool
    auto_commit: bool
    commit_window_hours: int
    created_at: datetime
    updated_at: datetime
    version: int

    @classmethod
    def from_dto(cls, dto: object) -> RotationPolicyResponse:
        data = dto.to_dict()  # type: ignore[attr-defined]
        data["policy_id"] = UUID(str(data["policy_id"]))
        data["tenant_id"] = str(data["tenant_id"])
        data["created_at"] = datetime.fromisoformat(str(data["created_at"]))
        data["updated_at"] = datetime.fromisoformat(str(data["updated_at"]))
        return cls(**data)


class CreateExpirationPolicyRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    name: str
    ttl_days: int
    warn_days_before: int
    hard_expire: bool


class UpdateExpirationPolicyRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    ttl_days: int
    warn_days_before: int
    hard_expire: bool


class ExpirationPolicyResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    policy_id: UUID
    tenant_id: str
    name: str
    ttl_days: int
    warn_days_before: int
    hard_expire: bool
    created_at: datetime
    updated_at: datetime
    version: int

    @classmethod
    def from_dto(cls, dto: object) -> ExpirationPolicyResponse:
        data = dto.to_dict()  # type: ignore[attr-defined]
        data["policy_id"] = UUID(str(data["policy_id"]))
        data["tenant_id"] = str(data["tenant_id"])
        data["created_at"] = datetime.fromisoformat(str(data["created_at"]))
        data["updated_at"] = datetime.fromisoformat(str(data["updated_at"]))
        return cls(**data)
