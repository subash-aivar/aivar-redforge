"""Audit log API schemas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AuditEntryResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    entry_id: UUID
    audit_log_id: UUID
    credential_id: UUID
    tenant_id: str
    operation: str
    outcome: str
    principal_id: UUID
    occurred_at: datetime
    detail: str
    client_ip: str | None
    request_id: str | None

    @classmethod
    def from_dto(cls, dto: object) -> AuditEntryResponse:
        data = dto.to_dict()  # type: ignore[attr-defined]
        for key in ("entry_id", "audit_log_id", "credential_id", "principal_id"):
            data[key] = UUID(str(data[key]))
        data["tenant_id"] = str(data["tenant_id"])
        data["occurred_at"] = datetime.fromisoformat(str(data["occurred_at"]))
        return cls(**data)


class ListAuditEntriesResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    items: list[AuditEntryResponse]
