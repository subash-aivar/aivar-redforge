"""Payload application DTOs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class PayloadVersionDTO:
    version: str
    payload_hash: str
    storage_ref: str
    technique_ids: tuple[str, ...]
    published_at: datetime
    vulnerability_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PayloadDTO:
    payload_id: str
    tenant_id: str
    payload_key: str
    payload_type: str
    impact_ceiling: str
    approval_state: str
    current_version: str | None
    versions: tuple[PayloadVersionDTO, ...]
    engagement_classes: tuple[str, ...]
    version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class PluginDTO:
    plugin_id: str
    tenant_id: str
    name: str
    plugin_type: str
    plugin_version: str
    plugin_hash: str
    technique_ids: tuple[str, ...]
    trust_level: str
    approval_state: str
    version: int
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class HashVerificationResultDTO:
    payload_id: str
    status: str
    payload_hash: str
