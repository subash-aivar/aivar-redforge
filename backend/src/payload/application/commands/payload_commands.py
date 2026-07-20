"""Payload application commands."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class RegisterPayload:
    tenant_id: UUID
    payload_key: str
    payload_type: str
    impact_ceiling: str
    engagement_classes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class PublishPayloadVersion:
    tenant_id: UUID
    payload_id: UUID
    version: str
    payload_hash: str
    storage_ref: str
    technique_ids: tuple[str, ...]
    vulnerability_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ApprovePayload:
    tenant_id: UUID
    payload_id: UUID
    approved_by: UUID
    signature: str
    ciso_approved: bool = False
    engagement_classes: tuple[str, ...] | None = None


@dataclass(frozen=True, slots=True)
class DeprecatePayload:
    tenant_id: UUID
    payload_id: UUID
    reason: str


@dataclass(frozen=True, slots=True)
class RevokePayload:
    tenant_id: UUID
    payload_id: UUID
    reason: str
    revoked_by: UUID


@dataclass(frozen=True, slots=True)
class VerifyPayloadHash:
    tenant_id: UUID
    payload_id: UUID
    computed_hash: str


@dataclass(frozen=True, slots=True)
class RegisterPlugin:
    tenant_id: UUID
    name: str
    plugin_type: str
    plugin_version: str
    plugin_hash: str
    technique_ids: tuple[str, ...]
    trust_level: str


@dataclass(frozen=True, slots=True)
class ApprovePlugin:
    tenant_id: UUID
    plugin_id: UUID
    approved_by: UUID


@dataclass(frozen=True, slots=True)
class RevokePlugin:
    tenant_id: UUID
    plugin_id: UUID
    reason: str
    revoked_by: UUID
