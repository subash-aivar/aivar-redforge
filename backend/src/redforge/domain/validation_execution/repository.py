"""Repository interfaces for the Gated Safe Active Validation bounded context."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.validation_execution.entity import ValidationExecution
    from redforge.domain.validation_execution.execution_event import ExecutionEvent
    from redforge.domain.validation_execution.value_objects import ExecutionStatus
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class ValidationExecutionRepository(Protocol):
    """Port for ValidationExecution persistence, always tenant-scoped."""

    async def get_by_id_for_organization(
        self, execution_id: EntityId, organization_id: EntityId
    ) -> ValidationExecution | None:
        """Returns None for a foreign-tenant id — callers must never
        distinguish this from "does not exist" in API responses."""
        ...

    async def get_by_id_for_organization_for_update(
        self, execution_id: EntityId, organization_id: EntityId
    ) -> ValidationExecution | None:
        """Locked read (SELECT ... FOR UPDATE against PostgreSQL) — used
        by cancellation and by the running loop's between-step
        cancellation check to avoid a race between a concurrent cancel
        request and step scheduling."""
        ...

    async def list_by_organization(
        self,
        organization_id: EntityId,
        status: ExecutionStatus | None,
        limit: int,
        offset: int,
    ) -> list[ValidationExecution]:
        ...

    async def count_by_status(self, organization_id: EntityId) -> dict[str, int]:
        ...

    async def save(self, execution: ValidationExecution) -> None:
        ...


@runtime_checkable
class ExecutionEventRepository(Protocol):
    """Port for the immutable, immediately-visible ExecutionEvent log."""

    async def append(self, event: ExecutionEvent) -> None:
        ...

    async def next_sequence(self, execution_id: EntityId) -> int:
        ...

    async def list_for_execution(
        self, execution_id: EntityId, organization_id: EntityId, after_sequence: int, limit: int,
    ) -> list[ExecutionEvent]:
        ...
