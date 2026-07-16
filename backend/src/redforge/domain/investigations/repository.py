"""Repository protocol for the Investigation bounded context — M21.

All I/O goes through this protocol. Infrastructure implementations
provide the real PostgreSQL behavior.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from datetime import datetime

    from redforge.domain.investigations.value_objects import (
        InvestigationSeverity,
        InvestigationStatus,
    )


@runtime_checkable
class InvestigationCaseRepository(Protocol):
    """Port for investigation case persistence."""

    async def create(self, model: Any) -> Any:
        """Persist a new investigation case.

        Returns the created model. On concurrent creation of the same
        correlation_key, the SAVEPOINT + refetch pattern ensures exactly
        one canonical case is returned.
        """
        ...

    async def get(self, organization_id: str, case_id: str) -> Any | None:
        """Load a case by ID within tenant boundary."""
        ...

    async def get_by_correlation_key(
        self, organization_id: str, correlation_key: str
    ) -> Any | None:
        """Load the active case for a correlation key, if any."""
        ...

    async def update_status(
        self,
        organization_id: str,
        case_id: str,
        new_status: InvestigationStatus,
        current_version: int,
        updates: dict[str, Any] | None = None,
    ) -> bool:
        """CAS update: only succeeds if current_version matches.

        Returns True if 1 row was updated, False on version mismatch.
        """
        ...

    async def update_evidence_metrics(
        self,
        organization_id: str,
        case_id: str,
        new_severity: InvestigationSeverity,
        new_last_observed_at: datetime,
        domain: str,
        entity_ids: list[str],
    ) -> None:
        """Update severity, last_observed_at, and entity tracking."""
        ...

    async def list_cases(
        self,
        organization_id: str,
        *,
        status: InvestigationStatus | None = None,
        severity: InvestigationSeverity | None = None,
        source_domain: str | None = None,
        since: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[Any]:
        """Paginated tenant-scoped case listing."""
        ...

    async def count_by_status(
        self, organization_id: str
    ) -> dict[str, int]:
        """Count cases grouped by status for posture metrics."""
        ...


@runtime_checkable
class InvestigationEvidenceRepository(Protocol):
    """Port for investigation evidence link persistence."""

    async def create_link(self, model: Any) -> Any:
        """Persist a new evidence link.

        On conflict on dedup_key: no-op (idempotent).
        """
        ...

    async def link_exists(
        self, organization_id: str, case_id: str, dedup_key: str
    ) -> bool:
        """Check if this dedup_key is already linked to the case."""
        ...

    async def list_for_case(
        self,
        organization_id: str,
        case_id: str,
        source_domain: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ) -> list[Any]:
        """List evidence links for a case (paginated)."""
        ...

    async def count_domains(
        self, organization_id: str, case_id: str
    ) -> int:
        """Count distinct source domains contributing to this case."""
        ...


@runtime_checkable
class InvestigationEventRepository(Protocol):
    """Port for investigation timeline event persistence."""

    async def create_event(self, model: Any) -> None:
        """Append a timeline event (idempotent on unique event_id)."""
        ...

    async def list_events(
        self,
        organization_id: str,
        case_id: str,
        limit: int = 200,
        offset: int = 0,
    ) -> list[Any]:
        """Chronological timeline events for a case (paginated)."""
        ...

    async def list_opened_events_since(
        self,
        organization_id: str,
        since: datetime,
        limit: int,
    ) -> list[Any]:
        """Stream integration: CASE_OPENED events for operational feed."""
        ...


@runtime_checkable
class CorrelationCursorRepository(Protocol):
    """Port for per-source worker cursor persistence."""

    async def get_cursor(self, source_domain: str) -> str | None:
        """Return the last-processed cursor for a source domain."""
        ...

    async def set_cursor(self, source_domain: str, cursor: str) -> None:
        """Persist the updated cursor after a processing cycle."""
        ...
