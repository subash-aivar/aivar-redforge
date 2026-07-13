"""Repository interface for the ValidationPolicy aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.policies.entity import ValidationPolicy
    from redforge.domain.policies.value_objects import PolicyStatus
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class PolicyRepository(Protocol):
    """Port for Validation Policy persistence operations."""

    async def get_by_id(self, policy_id: EntityId) -> ValidationPolicy | None:
        """Retrieve a policy by its unique identifier."""
        ...

    async def list_published(self) -> list[ValidationPolicy]:
        """List all published (executable) policies."""
        ...

    async def list_by_status(
        self, status: PolicyStatus
    ) -> list[ValidationPolicy]:
        """List policies filtered by status."""
        ...

    async def save(self, policy: ValidationPolicy) -> None:
        """Persist a new or updated policy."""
        ...
