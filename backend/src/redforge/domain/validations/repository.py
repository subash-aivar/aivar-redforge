"""Repository interface for the ValidationRun aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.validations.entity import ValidationRun
    from redforge.domain.validations.value_objects import ValidationStatus
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class ValidationRunRepository(Protocol):
    """Port for ValidationRun persistence operations."""

    async def get_by_id(self, run_id: EntityId) -> ValidationRun | None:
        """Retrieve a ValidationRun by its unique identifier."""
        ...

    async def list_by_target(
        self,
        target_id: EntityId,
        status: ValidationStatus | None = None,
    ) -> list[ValidationRun]:
        """List validation runs for a target, optionally filtered by status."""
        ...

    async def list_by_organization(
        self,
        organization_id: EntityId,
        status: ValidationStatus | None = None,
    ) -> list[ValidationRun]:
        """List validation runs for an organization."""
        ...

    async def save(self, run: ValidationRun) -> None:
        """Persist a new or updated ValidationRun."""
        ...
