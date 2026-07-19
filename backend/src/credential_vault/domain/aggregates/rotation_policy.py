"""RotationPolicy aggregate root."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from credential_vault.domain.events.policy_events import (
    RotationPolicyCreated,
    RotationPolicyDeleted,
    RotationPolicyUpdated,
)
from credential_vault.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    TenantMismatch,
)

if TYPE_CHECKING:
    from datetime import datetime

    from credential_vault.domain.events.base import BaseDomainEvent
    from credential_vault.domain.value_objects.identifiers import (
        PrincipalId,
        RotationPolicyId,
        TenantId,
    )


class RotationPolicy:
    __slots__ = (
        "_pending_events",
        "_version",
        "auto_rotate",
        "created_at",
        "interval_days",
        "max_versions_kept",
        "name",
        "notify_days_before",
        "policy_id",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        policy_id: RotationPolicyId,
        tenant_id: TenantId,
        name: str,
        interval_days: int | None,
        max_versions_kept: int,
        notify_days_before: int,
        auto_rotate: bool,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.policy_id = policy_id
        self.tenant_id = tenant_id
        self.name = name
        self.interval_days = interval_days
        self.max_versions_kept = max_versions_kept
        self.notify_days_before = notify_days_before
        self.auto_rotate = auto_rotate
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @classmethod
    def create(
        cls,
        policy_id: RotationPolicyId,
        tenant_id: TenantId,
        name: str,
        interval_days: int | None,
        max_versions_kept: int,
        notify_days_before: int,
        auto_rotate: bool,
        now: datetime,
    ) -> RotationPolicy:
        cls._validate(name, interval_days, max_versions_kept, notify_days_before)
        policy = cls(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name=name.strip(),
            interval_days=interval_days,
            max_versions_kept=max_versions_kept,
            notify_days_before=notify_days_before,
            auto_rotate=auto_rotate,
            created_at=now,
            updated_at=now,
            version=0,
        )
        policy._pending_events.append(
            RotationPolicyCreated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(policy_id),
                aggregate_type="RotationPolicy",
                policy_id=policy_id,
                name=policy.name,
                interval_days=interval_days,
                max_versions_kept=max_versions_kept,
                auto_rotate=auto_rotate,
            )
        )
        return policy

    @staticmethod
    def _validate(
        name: str,
        interval_days: int | None,
        max_versions_kept: int,
        notify_days_before: int,
    ) -> None:
        if not name or not name.strip():
            raise InvalidArgument("name", "name required")
        if len(name.strip()) > 256:
            raise InvalidArgument("name", "max 256 chars")
        if interval_days is not None and not (1 <= interval_days <= 3650):
            raise InvalidArgument("interval_days", "must be 1-3650")
        if not (1 <= max_versions_kept <= 100):
            raise InvalidArgument("max_versions_kept", "must be 1-100")
        if not (0 <= notify_days_before <= 90):
            raise InvalidArgument("notify_days_before", "must be 0-90")

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if self.tenant_id != tenant_id:
            raise TenantMismatch(expected=self.tenant_id, actual=tenant_id)

    def update(
        self,
        tenant_id: TenantId,
        interval_days: int | None,
        max_versions_kept: int,
        notify_days_before: int,
        auto_rotate: bool,
        principal: PrincipalId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._validate(self.name, interval_days, max_versions_kept, notify_days_before)
        changed: list[str] = []
        if interval_days != self.interval_days:
            changed.append("interval_days")
            self.interval_days = interval_days
        if max_versions_kept != self.max_versions_kept:
            changed.append("max_versions_kept")
            self.max_versions_kept = max_versions_kept
        if notify_days_before != self.notify_days_before:
            changed.append("notify_days_before")
            self.notify_days_before = notify_days_before
        if auto_rotate != self.auto_rotate:
            changed.append("auto_rotate")
            self.auto_rotate = auto_rotate
        _ = principal
        self._version += 1
        self.updated_at = now
        self._pending_events.append(
            RotationPolicyUpdated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.policy_id),
                aggregate_type="RotationPolicy",
                policy_id=self.policy_id,
                changed_fields=changed,
            )
        )

    def delete(
        self, tenant_id: TenantId, principal: PrincipalId, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self._version += 1
        self.updated_at = now
        self._pending_events.append(
            RotationPolicyDeleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.policy_id),
                aggregate_type="RotationPolicy",
                policy_id=self.policy_id,
                principal_id=principal,
            )
        )

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @property
    def version(self) -> int:
        return self._version
