"""Repository interface for the Evidence aggregate.

Note: Evidence is append-only. The repository has NO update() method.
Save always creates a new record or appends to an existing one.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.evidence.entity import Evidence
    from redforge.domain.evidence.value_objects import EvidenceResult
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class EvidenceRepository(Protocol):
    """Port for Evidence persistence operations.

    Evidence is immutable. There is no update semantic.
    Save persists; subsequent saves for the same ID are no-ops or
    raise an error depending on implementation.
    """

    async def get_by_id(self, evidence_id: EntityId) -> Evidence | None:
        """Retrieve a single Evidence by its unique identifier."""
        ...

    async def list_by_run(
        self,
        run_id: EntityId,
        result: EvidenceResult | None = None,
    ) -> list[Evidence]:
        """List all evidence for a validation run, optionally filtered by result."""
        ...

    async def list_by_target(
        self,
        target_id: EntityId,
        result: EvidenceResult | None = None,
    ) -> list[Evidence]:
        """List all evidence for a target, optionally filtered by result."""
        ...

    async def save(self, evidence: Evidence) -> None:
        """Persist a new piece of evidence. Append-only."""
        ...
