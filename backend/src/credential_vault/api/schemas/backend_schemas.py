"""Vault backend API schemas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class RegisterVaultBackendRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    name: str
    backend_type: str
    config: dict[str, str] = Field(default_factory=dict)
    is_default: bool = False


class VaultBackendResponse(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, frozen=True)

    backend_id: UUID
    tenant_id: str
    name: str
    backend_type: str
    is_default: bool
    created_at: datetime
    updated_at: datetime
    version: int

    @classmethod
    def from_dto(cls, dto: object) -> VaultBackendResponse:
        data = dto.to_dict()  # type: ignore[attr-defined]
        data["backend_id"] = UUID(str(data["backend_id"]))
        data["tenant_id"] = str(data["tenant_id"])
        data["created_at"] = datetime.fromisoformat(str(data["created_at"]))
        data["updated_at"] = datetime.fromisoformat(str(data["updated_at"]))
        return cls(**data)
