"""Runtime health transition detection — M15.

`application/platform/dynamic_health.py` health probes stay exactly as
they were: live-computed, no memory of prior state. This module is the
ONLY thing in M15 that adds persistence for runtime health, and it adds
the absolute minimum needed to detect a genuine HEALTHY<->UNHEALTHY
flip exactly once — never to re-derive "is this healthy right now"
(the /runtime read endpoint always calls the live health engine
directly for that, never this table).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.application.platform.health_engine import RuntimeHealthEngine


class RuntimeHealthTransitionProjector:
    """Polls RuntimeHealthEngine.aggregate_health() once and durably
    records any genuine per-component status transition. Safe to call
    concurrently from multiple process instances — see
    SqlAlchemyRuntimeHealthRepository.record_transition_if_changed()'s
    own docstring for the row-lock argument."""

    def __init__(
        self,
        health_engine: RuntimeHealthEngine,
        session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        self._health_engine = health_engine
        self._session_factory = session_factory

    async def check_and_record_transitions(self) -> list[tuple[str, str, str]]:
        """Returns a list of (component_id, old_status, new_status) for
        every genuine transition recorded this call — empty on a
        no-change poll, which is the overwhelmingly common case."""
        from redforge.infrastructure.database.repositories.runtime_health_repository import (
            SqlAlchemyRuntimeHealthRepository,
        )
        from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork

        aggregated = await self._health_engine.aggregate_health()
        now = utc_now()
        transitions: list[tuple[str, str, str]] = []
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyRuntimeHealthRepository(uow.session)
            for component in aggregated.components:
                old_status = await repo.record_transition_if_changed(
                    transition_id=str(EntityId.generate()),
                    component_id=component.component_id,
                    new_status=str(component.status),
                    now=now,
                )
                if old_status is not None:
                    transitions.append((component.component_id, old_status, str(component.status)))
            await uow.commit()
        return transitions
