"""Rotation and expiration policy command dataclasses (CQRS write side)."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID  # noqa: TC003 — runtime type for frozen dataclass fields


@dataclass(frozen=True, slots=True)
class CreateRotationPolicyCommand:
    tenant_id: UUID
    principal_id: UUID
    name: str
    interval_days: int | None
    max_versions_kept: int
    notify_days_before: int
    auto_rotate: bool


@dataclass(frozen=True, slots=True)
class UpdateRotationPolicyCommand:
    tenant_id: UUID
    policy_id: UUID
    principal_id: UUID
    interval_days: int | None
    max_versions_kept: int
    notify_days_before: int
    auto_rotate: bool


@dataclass(frozen=True, slots=True)
class DeleteRotationPolicyCommand:
    tenant_id: UUID
    policy_id: UUID
    principal_id: UUID


@dataclass(frozen=True, slots=True)
class CreateExpirationPolicyCommand:
    tenant_id: UUID
    principal_id: UUID
    name: str
    ttl_days: int
    warn_days_before: int
    hard_expire: bool


@dataclass(frozen=True, slots=True)
class UpdateExpirationPolicyCommand:
    tenant_id: UUID
    policy_id: UUID
    principal_id: UUID
    ttl_days: int
    warn_days_before: int
    hard_expire: bool


@dataclass(frozen=True, slots=True)
class DeleteExpirationPolicyCommand:
    tenant_id: UUID
    policy_id: UUID
    principal_id: UUID
