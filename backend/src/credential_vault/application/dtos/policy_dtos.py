"""Rotation and expiration policy DTOs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from credential_vault.domain.aggregates.expiration_policy import ExpirationPolicy
    from credential_vault.domain.aggregates.rotation_policy import RotationPolicy


@dataclass(frozen=True, slots=True)
class RotationPolicyDTO:
    policy_id: str
    tenant_id: str
    name: str
    interval_days: int | None
    max_versions_kept: int
    notify_days_before: int
    auto_rotate: bool
    auto_commit: bool
    commit_window_hours: int
    created_at: str
    updated_at: str
    version: int

    @classmethod
    def from_aggregate(cls, policy: RotationPolicy) -> Self:
        return cls(
            policy_id=str(policy.policy_id),
            tenant_id=str(policy.tenant_id),
            name=policy.name,
            interval_days=policy.interval_days,
            max_versions_kept=policy.max_versions_kept,
            notify_days_before=policy.notify_days_before,
            auto_rotate=policy.auto_rotate,
            auto_commit=policy.auto_commit,
            commit_window_hours=policy.commit_window_hours,
            created_at=policy.created_at.isoformat(),
            updated_at=policy.updated_at.isoformat(),
            version=policy.version,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "policy_id": self.policy_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "interval_days": self.interval_days,
            "max_versions_kept": self.max_versions_kept,
            "notify_days_before": self.notify_days_before,
            "auto_rotate": self.auto_rotate,
            "auto_commit": self.auto_commit,
            "commit_window_hours": self.commit_window_hours,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class ExpirationPolicyDTO:
    policy_id: str
    tenant_id: str
    name: str
    ttl_days: int
    warn_days_before: int
    hard_expire: bool
    created_at: str
    updated_at: str
    version: int

    @classmethod
    def from_aggregate(cls, policy: ExpirationPolicy) -> Self:
        return cls(
            policy_id=str(policy.policy_id),
            tenant_id=str(policy.tenant_id),
            name=policy.name,
            ttl_days=policy.ttl_days,
            warn_days_before=policy.warn_days_before,
            hard_expire=policy.hard_expire,
            created_at=policy.created_at.isoformat(),
            updated_at=policy.updated_at.isoformat(),
            version=policy.version,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "policy_id": self.policy_id,
            "tenant_id": self.tenant_id,
            "name": self.name,
            "ttl_days": self.ttl_days,
            "warn_days_before": self.warn_days_before,
            "hard_expire": self.hard_expire,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "version": self.version,
        }
