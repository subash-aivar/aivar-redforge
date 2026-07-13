"""Repository interface for the Finding aggregate."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.findings.entity import Finding
    from redforge.domain.findings.value_objects import FindingStatus, Severity
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class FindingRepository(Protocol):
    """Port for Finding persistence operations."""

    async def get_by_id(self, finding_id: EntityId) -> Finding | None:
        """Retrieve a Finding by its unique identifier."""
        ...

    async def list_by_run(
        self,
        run_id: EntityId,
        severity: Severity | None = None,
        status: FindingStatus | None = None,
    ) -> list[Finding]:
        """List findings for a validation run."""
        ...

    async def list_by_target(
        self,
        target_id: EntityId,
        severity: Severity | None = None,
        status: FindingStatus | None = None,
    ) -> list[Finding]:
        """List findings for an AI target."""
        ...

    async def save(self, finding: Finding) -> None:
        """Persist a new or updated Finding."""
        ...
