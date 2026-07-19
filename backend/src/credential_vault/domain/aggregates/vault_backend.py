"""VaultBackend aggregate root."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from credential_vault.domain.events.backend_events import (
    VaultBackendDeleted,
    VaultBackendRegistered,
)
from credential_vault.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    TenantMismatch,
)

if TYPE_CHECKING:
    from datetime import datetime

    from credential_vault.domain.events.base import BaseDomainEvent
    from credential_vault.domain.value_objects.audit_types import VaultBackendType
    from credential_vault.domain.value_objects.identifiers import (
        PrincipalId,
        TenantId,
        VaultBackendId,
    )


class VaultBackend:
    __slots__ = (
        "_pending_events",
        "_version",
        "backend_id",
        "backend_type",
        "config",
        "created_at",
        "is_default",
        "name",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        backend_id: VaultBackendId,
        tenant_id: TenantId,
        name: str,
        backend_type: VaultBackendType,
        config: dict[str, str],
        is_default: bool,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.backend_id = backend_id
        self.tenant_id = tenant_id
        self.name = name
        self.backend_type = backend_type
        self.config = dict(config)
        self.is_default = is_default
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @classmethod
    def create(
        cls,
        backend_id: VaultBackendId,
        tenant_id: TenantId,
        name: str,
        backend_type: VaultBackendType,
        config: dict[str, str],
        is_default: bool,
        now: datetime,
    ) -> VaultBackend:
        if not name or not name.strip():
            raise InvalidArgument("name", "name required")
        if len(name.strip()) > 256:
            raise InvalidArgument("name", "max 256 chars")
        if len(config) > 100:
            raise InvalidArgument("config", "max 100 keys")
        for value in config.values():
            if len(value) > 2048:
                raise InvalidArgument("config", "value max 2048 chars")
        backend = cls(
            backend_id=backend_id,
            tenant_id=tenant_id,
            name=name.strip(),
            backend_type=backend_type,
            config=config,
            is_default=is_default,
            created_at=now,
            updated_at=now,
            version=0,
        )
        backend._pending_events.append(
            VaultBackendRegistered(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(backend_id),
                aggregate_type="VaultBackend",
                backend_id=backend_id,
                name=backend.name,
                backend_type=backend_type,
                is_default=is_default,
            )
        )
        return backend

    def delete(
        self, tenant_id: TenantId, principal: PrincipalId, now: datetime
    ) -> None:
        if self.tenant_id != tenant_id:
            raise TenantMismatch(expected=self.tenant_id, actual=tenant_id)
        self._version += 1
        self.updated_at = now
        self._pending_events.append(
            VaultBackendDeleted(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.backend_id),
                aggregate_type="VaultBackend",
                backend_id=self.backend_id,
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
