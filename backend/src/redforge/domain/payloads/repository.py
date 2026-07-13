"""Repository interface for the Payload Template aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.payloads.entity import PayloadTemplate
    from redforge.domain.payloads.value_objects import TemplateType
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class PayloadTemplateRepository(Protocol):
    """Port for PayloadTemplate persistence operations."""

    async def get_by_id(self, template_id: EntityId) -> PayloadTemplate | None:
        """Retrieve a template by its unique identifier."""
        ...

    async def list_by_attack(self, attack_id: str) -> list[PayloadTemplate]:
        """List all published templates for an attack definition."""
        ...

    async def list_by_type(
        self, template_type: TemplateType
    ) -> list[PayloadTemplate]:
        """List templates by type."""
        ...

    async def save(self, template: PayloadTemplate) -> None:
        """Persist a new or updated template."""
        ...
