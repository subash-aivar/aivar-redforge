"""Rotation and expiration policy domain events."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from credential_vault.domain.events.base import BaseDomainEvent

if TYPE_CHECKING:
    from credential_vault.domain.value_objects.identifiers import (
        ExpirationPolicyId,
        PrincipalId,
        RotationPolicyId,
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class RotationPolicyCreated(BaseDomainEvent):
    policy_id: RotationPolicyId
    name: str
    interval_days: int | None
    max_versions_kept: int
    auto_rotate: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class RotationPolicyUpdated(BaseDomainEvent):
    policy_id: RotationPolicyId
    changed_fields: list[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class RotationPolicyDeleted(BaseDomainEvent):
    policy_id: RotationPolicyId
    principal_id: PrincipalId


@dataclass(frozen=True, slots=True, kw_only=True)
class ExpirationPolicyCreated(BaseDomainEvent):
    policy_id: ExpirationPolicyId
    name: str
    ttl_days: int
    warn_days_before: int
    hard_expire: bool


@dataclass(frozen=True, slots=True, kw_only=True)
class ExpirationPolicyUpdated(BaseDomainEvent):
    policy_id: ExpirationPolicyId
    changed_fields: list[str]


@dataclass(frozen=True, slots=True, kw_only=True)
class ExpirationPolicyDeleted(BaseDomainEvent):
    policy_id: ExpirationPolicyId
    principal_id: PrincipalId
