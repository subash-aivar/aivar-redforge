"""Protocol contracts for the Red Team application layer — Sprint 34/35.

All collaborators injected into RedTeamOrchestrator are defined here
as @runtime_checkable Protocols. No concrete implementations are imported.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.red_team.entity import AttackGraph


@runtime_checkable
class AttackGraphRepositoryPort(Protocol):
    """Persists and retrieves AttackGraph instances.

    The in-memory implementation is the default (tests + dev).
    Production uses a PostgreSQL-backed implementation.
    """

    async def save(self, graph: AttackGraph) -> None:
        """Persist or update an AttackGraph."""
        ...

    async def get(self, graph_id: str) -> AttackGraph | None:
        """Retrieve an AttackGraph by ID; returns None if not found."""
        ...
