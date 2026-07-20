"""Payload and plugin domain events."""

from __future__ import annotations

from dataclasses import dataclass

from payload.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class PayloadRegistered(BaseDomainEvent):
    payload_key: str
    payload_type: str
    impact_ceiling: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PayloadVersionPublished(BaseDomainEvent):
    version: str
    payload_hash: str
    storage_ref: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PayloadApproved(BaseDomainEvent):
    version: str
    approved_by: str
    ciso_approved: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class PayloadDeprecated(BaseDomainEvent):
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PayloadRevoked(BaseDomainEvent):
    reason: str
    revoked_by: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PayloadHashVerified(BaseDomainEvent):
    version: str
    payload_hash: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PayloadHashMismatchDetected(BaseDomainEvent):
    version: str
    expected_hash: str
    computed_hash: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PluginRegistered(BaseDomainEvent):
    plugin_type: str
    plugin_version: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PluginApproved(BaseDomainEvent):
    approved_by: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PluginRevoked(BaseDomainEvent):
    reason: str
    revoked_by: str
