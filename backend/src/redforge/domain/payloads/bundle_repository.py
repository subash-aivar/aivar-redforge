"""Repository interface for the PayloadBundle aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.payloads.bundle import PayloadBundle
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class PayloadBundleRepository(Protocol):
    """Port for PayloadBundle persistence operations."""

    async def get_by_id(self, bundle_id: EntityId) -> PayloadBundle | None:
        """Retrieve a bundle by its unique identifier."""
        ...

    async def get_active_for_plan(self, attack_plan_id: EntityId) -> PayloadBundle | None:
        """Retrieve the currently active (non-superseded) bundle for an
        attack plan, if one exists."""
        ...

    async def save(self, bundle: PayloadBundle) -> None:
        """Persist a new or updated (e.g. just-superseded) bundle."""
        ...
