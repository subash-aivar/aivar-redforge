"""Drift persistence + read API — M14.

Thin persistence wrapper around `drift_detector.py`'s pure comparison
functions and `SqlAlchemySecurityDriftEventRepository`'s append-only
log. Kept separate from the pure detector so the detector itself stays
trivially unit-testable with no database at all.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.infrastructure.database.repositories.continuous_validation.drift_repository import (
    SqlAlchemySecurityDriftEventRepository,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from redforge.domain.continuous_validation.entity import SecurityDriftEvent


def _safe_entity_id(value: str) -> EntityId | None:
    """A client-supplied id that is not a syntactically valid EntityId
    can never resolve to a real row — treated the same as "not found"
    rather than propagating EntityId.from_string()'s raw ValueError
    into an unhandled 500."""
    try:
        return EntityId.from_string(value)
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class SecurityDriftEventDTO:
    id: str
    organization_id: str
    continuous_policy_id: str
    execution_id: str
    category: str
    identity_key: str
    summary: str
    detail: dict[str, str]
    detected_at: str

    @classmethod
    def from_entity(cls, event: SecurityDriftEvent) -> SecurityDriftEventDTO:
        return cls(
            id=str(event.id),
            organization_id=str(event.organization_id),
            continuous_policy_id=str(event.continuous_policy_id),
            execution_id=str(event.execution_id),
            category=str(event.category),
            identity_key=event.identity_key,
            summary=event.summary,
            detail=event.detail,
            detected_at=event.detected_at.isoformat(),
        )


class SecurityDriftService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def persist(self, events: list[SecurityDriftEvent]) -> int:
        """Appends every event, skipping any that collide with an
        already-persisted (execution_id, category, identity_key) row —
        a documented no-op, never an error (see
        SqlAlchemySecurityDriftEventRepository.append()'s own
        docstring). Returns the count actually persisted."""
        if not events:
            return 0
        persisted = 0
        async with self._session_factory() as session:
            repo = SqlAlchemySecurityDriftEventRepository(session)
            for event in events:
                if await repo.append(event):
                    persisted += 1
            await session.commit()
        return persisted

    async def list_for_policy(
        self,
        continuous_policy_id: str,
        organization_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[SecurityDriftEventDTO]:
        policy_id = _safe_entity_id(continuous_policy_id)
        org_id = _safe_entity_id(organization_id)
        if policy_id is None or org_id is None:
            return []
        async with self._session_factory() as session:
            repo = SqlAlchemySecurityDriftEventRepository(session)
            events = await repo.list_for_policy(policy_id, org_id, limit, offset)
        return [SecurityDriftEventDTO.from_entity(e) for e in events]

    async def list_for_org(
        self,
        organization_id: str,
        limit: int = 100,
        offset: int = 0,
    ) -> list[SecurityDriftEventDTO]:
        """Org-wide change feed across every policy — used by the
        change-feed endpoint, not the per-policy drift list."""
        async with self._session_factory() as session:
            repo = SqlAlchemySecurityDriftEventRepository(session)
            events = await repo.list_for_organization(
                EntityId.from_string(organization_id), limit, offset,
            )
        return [SecurityDriftEventDTO.from_entity(e) for e in events]

    async def get(
        self, drift_event_id: str, organization_id: str,
    ) -> SecurityDriftEventDTO | None:
        event_id = _safe_entity_id(drift_event_id)
        org_id = _safe_entity_id(organization_id)
        if event_id is None or org_id is None:
            return None
        async with self._session_factory() as session:
            repo = SqlAlchemySecurityDriftEventRepository(session)
            event = await repo.get_for_organization(event_id, org_id)
        return SecurityDriftEventDTO.from_entity(event) if event is not None else None
