"""Repository ports for runtime visibility."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from redforge.domain.cloud_security.runtime.entities import RuntimeArtifact
from redforge.domain.cloud_security.runtime.event import CloudRuntimeEvent
from redforge.domain.cloud_security.runtime.process import (
    RuntimeFileActivity,
    RuntimeNetworkConnection,
    RuntimeProcess,
)
from redforge.domain.cloud_security.runtime.session import (
    RuntimeExecutionContext,
    RuntimeIdentitySession,
)
from redforge.domain.cloud_security.value_objects import OrganizationId


class RuntimeEventRepository(Protocol):
    async def save(self, event: CloudRuntimeEvent) -> None: ...

    async def save_batch(self, events: list[CloudRuntimeEvent]) -> int:
        """Persist events; return count newly inserted (dedup may skip)."""
        ...

    async def get_by_id(
        self, event_id: UUID, *, organization_id: OrganizationId
    ) -> CloudRuntimeEvent | None: ...

    async def list_by_organization(
        self,
        organization_id: OrganizationId,
        *,
        since: datetime | None = None,
        event_type: str | None = None,
        source: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CloudRuntimeEvent]: ...

    async def list_by_account(
        self,
        cloud_account_id: UUID,
        *,
        organization_id: OrganizationId,
        since: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[CloudRuntimeEvent]: ...

    async def count_by_organization(
        self, organization_id: OrganizationId, *, since: datetime | None = None
    ) -> int: ...


class RuntimeArtifactRepository(Protocol):
    async def save_for_event(
        self,
        *,
        organization_id: OrganizationId,
        runtime_event_id: UUID,
        artifacts: list[RuntimeArtifact],
    ) -> None: ...

    async def list_by_event(
        self, runtime_event_id: UUID, *, organization_id: OrganizationId
    ) -> list[RuntimeArtifact]: ...


class RuntimeProcessRepository(Protocol):
    async def save(self, process: RuntimeProcess) -> None: ...

    async def save_batch(self, processes: list[RuntimeProcess]) -> None: ...

    async def list_by_organization(
        self, organization_id: OrganizationId, *, limit: int = 100, offset: int = 0
    ) -> list[RuntimeProcess]: ...


class RuntimeNetworkConnectionRepository(Protocol):
    async def save(self, connection: RuntimeNetworkConnection) -> None: ...

    async def save_batch(self, connections: list[RuntimeNetworkConnection]) -> None: ...

    async def list_by_organization(
        self, organization_id: OrganizationId, *, limit: int = 100, offset: int = 0
    ) -> list[RuntimeNetworkConnection]: ...


class RuntimeFileActivityRepository(Protocol):
    async def save(self, activity: RuntimeFileActivity) -> None: ...


class RuntimeIdentitySessionRepository(Protocol):
    async def save(self, session: RuntimeIdentitySession) -> None: ...


class RuntimeExecutionContextRepository(Protocol):
    async def save(self, context: RuntimeExecutionContext) -> None: ...
