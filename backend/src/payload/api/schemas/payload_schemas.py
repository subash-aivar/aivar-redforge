"""API request/response schemas for payload."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field

from payload.application.dtos.payload_dtos import (
    HashVerificationResultDTO,
    PayloadDTO,
    PluginDTO,
)


class RegisterPayloadRequest(BaseModel):
    payload_key: str = Field(min_length=3, max_length=256)
    payload_type: str
    impact_ceiling: str
    engagement_classes: list[str] = Field(default_factory=list)


class PublishPayloadVersionRequest(BaseModel):
    version: str = Field(min_length=1, max_length=64)
    payload_hash: str = Field(min_length=64, max_length=64)
    storage_ref: str = Field(min_length=1, max_length=512)
    technique_ids: list[str] = Field(min_length=1)
    vulnerability_refs: list[str] = Field(default_factory=list)


class ApprovePayloadRequest(BaseModel):
    approved_by: UUID
    signature: str = Field(min_length=1)
    ciso_approved: bool = False
    engagement_classes: list[str] | None = None


class DeprecatePayloadRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2048)


class RevokePayloadRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=2048)
    revoked_by: UUID


class VerifyPayloadHashRequest(BaseModel):
    computed_hash: str = Field(min_length=64, max_length=64)


class RegisterPluginRequest(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    plugin_type: str
    plugin_version: str
    plugin_hash: str = Field(min_length=64, max_length=64)
    technique_ids: list[str] = Field(min_length=1)
    trust_level: str


class ApprovePluginRequest(BaseModel):
    approved_by: UUID


class PayloadVersionResponse(BaseModel):
    version: str
    payload_hash: str
    storage_ref: str
    technique_ids: list[str]
    published_at: datetime
    vulnerability_refs: list[str]


class PayloadResponse(BaseModel):
    payload_id: str
    tenant_id: str
    payload_key: str
    payload_type: str
    impact_ceiling: str
    approval_state: str
    current_version: str | None
    versions: list[PayloadVersionResponse]
    engagement_classes: list[str]
    version: int
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_dto(cls, dto: PayloadDTO) -> PayloadResponse:
        return cls(
            payload_id=dto.payload_id,
            tenant_id=str(dto.tenant_id),
            payload_key=dto.payload_key,
            payload_type=dto.payload_type,
            impact_ceiling=dto.impact_ceiling,
            approval_state=dto.approval_state,
            current_version=dto.current_version,
            versions=[
                PayloadVersionResponse(
                    version=v.version,
                    payload_hash=v.payload_hash,
                    storage_ref=v.storage_ref,
                    technique_ids=list(v.technique_ids),
                    published_at=v.published_at,
                    vulnerability_refs=list(v.vulnerability_refs),
                )
                for v in dto.versions
            ],
            engagement_classes=list(dto.engagement_classes),
            version=dto.version,
            created_at=dto.created_at,
            updated_at=dto.updated_at,
        )


class ListPayloadsResponse(BaseModel):
    items: list[PayloadResponse]


class PluginResponse(BaseModel):
    plugin_id: str
    tenant_id: str
    name: str
    plugin_type: str
    plugin_version: str
    plugin_hash: str
    technique_ids: list[str]
    trust_level: str
    approval_state: str
    version: int
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_dto(cls, dto: PluginDTO) -> PluginResponse:
        return cls(
            plugin_id=dto.plugin_id,
            tenant_id=str(dto.tenant_id),
            name=dto.name,
            plugin_type=dto.plugin_type,
            plugin_version=dto.plugin_version,
            plugin_hash=dto.plugin_hash,
            technique_ids=list(dto.technique_ids),
            trust_level=dto.trust_level,
            approval_state=dto.approval_state,
            version=dto.version,
            created_at=dto.created_at,
            updated_at=dto.updated_at,
        )


class ListPluginsResponse(BaseModel):
    items: list[PluginResponse]


class HashVerificationResponse(BaseModel):
    payload_id: str
    status: str
    payload_hash: str

    @classmethod
    def from_dto(cls, dto: HashVerificationResultDTO) -> HashVerificationResponse:
        return cls(
            payload_id=dto.payload_id,
            status=dto.status,
            payload_hash=dto.payload_hash,
        )
