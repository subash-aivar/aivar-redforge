"""ExpirationPolicy aggregate root."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from credential_vault.domain.events.policy_events import (
    ExpirationPolicyCreated,
    ExpirationPolicyDeleted,
    ExpirationPolicyUpdated,
)
from credential_vault.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    TenantMismatch,
)

if TYPE_CHECKING:
    from datetime import datetime

    from credential_vault.domain.events.base import BaseDomainEvent
    from credential_vault.domain.value_objects.identifiers import (
        ExpirationPolicyId,
        PrincipalId,
        TenantId,
    )


class ExpirationPolicy:
    __slots__ = (
        "_pending_events",
        "_version",
        "created_at",
        "hard_expire",
        "name",
        "policy_id",
        "tenant_id",
        "ttl_days",
        "updated_at",
        "warn_days_before",
    )

    def __init__(
        self,
        policy_id: ExpirationPolicyId,
        tenant_id: TenantId,
        name: str,
        ttl_days: int,
        warn_days_before: int,
        hard_expire: bool,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.policy_id = policy_id
        self.tenant_id = tenant_id
        self.name = name
        self.ttl_days = ttl_days
        self.warn_days_before = warn_days_before
        self.hard_expire = hard_expire
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @classmethod
    def create(
        cls,
        policy_id: ExpirationPolicyId,
        tenant_id: TenantId,
        name: str,
        ttl_days: int,
        warn_days_before: int,
        hard_expire: bool,
        now: datetime,
    ) -> ExpirationPolicy:
        cls._validate(name, ttl_days, warn_days_before)
        policy = cls(
            policy_id=policy_id,
            tenant_id=tenant_id,
            name=name.strip(),
            ttl_days=ttl_days,
            warn_days_before=warn_days_before,
            hard_expire=hard_expire,
            created_at=now,
            updated_at=now,
            version=0,
        )
        policy._pending_events.append(
            ExpirationPolicyCreated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(policy_id),
                aggregate_type="ExpirationPolicy",
                policy_id=policy_id,
                name=policy.name,
                ttl_days=ttl_days,
                warn_days_before=warn_days_before,
                hard_expire=hard_expire,
            )
        )
        return policy

    @staticmethod
    def _validate(name: str, ttl_days: int, warn_days_before: int) -> None:
        if not name or not name.strip():
            raise InvalidArgument("name", "name required")
        if len(name.strip()) > 256:
            raise InvalidArgument("name", "max 256 chars")
        if not (1 <= ttl_days <= 3650):
            raise InvalidArgument("ttl_days", "must be 1-3650")
        if not (1 <= warn_days_before <= 90):
            raise InvalidArgument("warn_days_before", "must be 1-90")
        if warn_days_before >= ttl_days:
            raise InvalidArgument("warn_days_before", "must be < ttl_days")

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if self.tenant_id != tenant_id:
            raise TenantMismatch(expected=self.tenant_id, actual=tenant_id)

    def update(
        self,
        tenant_id: TenantId,
        ttl_days: int,
        warn_days_before: int,
        hard_expire: bool,
        principal: PrincipalId,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._validate(self.name, ttl_days, warn_days_before)
        changed: list[str] = []
        if ttl_days != self.ttl_days:
            changed.append("ttl_days")
            self.ttl_days = ttl_days
        if warn_days_before != self.warn_days_before:
            changed.append("warn_days_before")
            self.warn_days_before = warn_days_before
        if hard_expire != self.hard_expire:
            changed.append("hard_expire")
            self.hard_expire = hard_expire
        _ = principal
        self._version += 1
        self.updated_at = now
        self._pending_events.append(
            ExpirationPolicyUpdated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.policy_id),
                aggregate_type="ExpirationPolicy",
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
            ExpirationPolicyDeleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.policy_id),
                aggregate_type="ExpirationPolicy",
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
