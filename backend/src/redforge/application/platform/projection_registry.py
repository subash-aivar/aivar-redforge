"""ProjectionRegistry — Sprint 30.

Single source of truth for all registered projections.

Design rules:
- No imports from infrastructure layer.
- Registry is constructed once at startup and stored in RuntimeContainer.
- Duplicate projection_name is rejected at registration time → startup fails.
- Empty projection_name is rejected → startup fails.
- register_all_with() wires every projection into an engine in one call.
- All metadata is exposed for diagnostic endpoints.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from redforge.application.platform.idempotent_projection_engine import (
        IdempotentProjectionEngine,
    )
    from redforge.application.platform.projections.base import ProjectionBase


class ProjectionRegistrationError(RuntimeError):
    """Raised when a projection cannot be registered."""


class ProjectionRegistry:
    """Holds all projection instances and wires them into engines on demand.

    One instance lives in RuntimeContainer for the process lifetime.
    New projections are registered at startup before any events are processed.
    """

    def __init__(self) -> None:
        self._projections: list[ProjectionBase] = []
        self._names: set[str] = set()

    def register(self, projection: ProjectionBase) -> None:
        """Register a projection. Raises ProjectionRegistrationError on duplicates."""
        name = projection.projection_name
        if not name:
            raise ProjectionRegistrationError(
                f"{type(projection).__name__} has no projection_name — "
                "set the class-level projection_name attribute"
            )
        if name in self._names:
            raise ProjectionRegistrationError(
                f"Duplicate projection_name {name!r} — "
                f"already registered by {self._projection_type_for(name)}"
            )
        self._names.add(name)
        self._projections.append(projection)

    def register_all_with(self, engine: IdempotentProjectionEngine) -> None:
        """Wire every registered projection into the given engine."""
        for proj in self._projections:
            proj.register_with(engine)  # type: ignore[arg-type]

    def validate(self) -> None:
        """Raise if no projections are registered (startup guard)."""
        if not self._projections:
            raise ProjectionRegistrationError(
                "ProjectionRegistry is empty — replay would be a no-op. "
                "Wire projections in build_runtime_container before starting."
            )

    # ── Diagnostics ────────────────────────────────────────────────────────

    @property
    def count(self) -> int:
        return len(self._projections)

    @property
    def projection_names(self) -> list[str]:
        return [p.projection_name for p in self._projections]

    def info(self) -> list[dict[str, str]]:
        return [
            {
                "name": p.projection_name,
                "type": type(p).__name__,
            }
            for p in self._projections
        ]

    def clone(self) -> ProjectionRegistry:
        """Create a new ProjectionRegistry with fresh isolated projection instances.

        Each projection in the clone gets its own InMemoryReadModelRepository so that
        concurrent replay workers cannot race on shared mutable state (DEBT-S31-1).

        Limitation: cloned instances start at zero cumulative state. Use only when
        the caller controls the full replay sequence from position 0, or when the
        projection state will be initialized from an external repo before processing.

        Returns:
            New registry with same projection types but isolated repos.
        """
        from redforge.application.platform.projection_engine import InMemoryReadModelRepository

        new_registry = ProjectionRegistry()
        isolated_repo = InMemoryReadModelRepository()
        for proj in self._projections:
            new_proj = type(proj)(isolated_repo)  # type: ignore[call-arg]
            new_registry.register(new_proj)
        return new_registry

    async def flush_all_to_durable_repo(self, target_repo: Any, organization_id: str) -> None:
        """Flush all registered projection read models to target_repo.

        Called after replay engine.process() to persist the updated in-memory
        read model state to PostgreSQL within the same transaction boundary.

        Args:
            target_repo: PostgreSQLReadModelRepository (duck typing).
            organization_id: The org whose read models should be flushed.
        """
        for proj in self._projections:
            await proj.flush_to_durable_repo(target_repo, organization_id)

    @property
    def projections(self) -> list[ProjectionBase]:
        """Return the list of registered projection instances (read-only copy)."""
        return list(self._projections)

    def _projection_type_for(self, name: str) -> str:
        for p in self._projections:
            if p.projection_name == name:
                return type(p).__name__
        return "unknown"
