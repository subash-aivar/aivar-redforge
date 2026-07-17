"""`AttackPath` aggregate root — M22 Phase 5.

Holds summary state only. Steps are persisted and loaded via
`AttackPathStepRepository` (Hardening Review P0: unbounded collection
anti-pattern).
"""

from __future__ import annotations

from datetime import UTC, datetime

from redforge.domain.attack_path.events import (
    AttackPathComputed,
    AttackPathDomainEvent,
    AttackPathUpdated,
)
from redforge.domain.attack_path.exceptions import InvalidPathStatusTransitionError
from redforge.domain.attack_path.value_objects import PathConfidence, PathStatus

_ALLOWED: dict[PathStatus, frozenset[PathStatus]] = {
    PathStatus.ACTIVE: frozenset({PathStatus.CONTAINED, PathStatus.HISTORICAL}),
    PathStatus.CONTAINED: frozenset({PathStatus.HISTORICAL}),
    PathStatus.HISTORICAL: frozenset(),
}


class AttackPath:
    """Tenant-scoped evidence-backed attack path summary."""

    __slots__ = (
        "_attributed_actors",
        "_created_at",
        "_events",
        "_evidence_count",
        "_first_step_at",
        "_id",
        "_last_step_at",
        "_max_exposure_score",
        "_organization_id",
        "_path_confidence",
        "_root_canonical_key",
        "_root_entity_id",
        "_status",
        "_step_count",
        "_technique_coverage",
        "_terminal_entity_id",
        "_updated_at",
    )

    def __init__(
        self,
        *,
        id: str,
        organization_id: str,
        root_entity_id: str,
        root_canonical_key: str,
        terminal_entity_id: str | None,
        path_confidence: PathConfidence,
        technique_coverage: list[str],
        attributed_actors: list[str],
        step_count: int,
        evidence_count: int,
        max_exposure_score: float,
        first_step_at: datetime | None,
        last_step_at: datetime | None,
        status: PathStatus,
        created_at: datetime,
        updated_at: datetime,
    ) -> None:
        self._id = id
        self._organization_id = organization_id
        self._root_entity_id = root_entity_id
        self._root_canonical_key = root_canonical_key
        self._terminal_entity_id = terminal_entity_id
        self._path_confidence = path_confidence
        self._technique_coverage = list(technique_coverage)
        self._attributed_actors = list(attributed_actors)
        self._step_count = step_count
        self._evidence_count = evidence_count
        self._max_exposure_score = max_exposure_score
        self._first_step_at = first_step_at
        self._last_step_at = last_step_at
        self._status = status
        self._created_at = created_at
        self._updated_at = updated_at
        self._events: list[AttackPathDomainEvent] = []

    @classmethod
    def create_computed(
        cls,
        *,
        id: str,
        organization_id: str,
        root_entity_id: str,
        root_canonical_key: str,
        terminal_entity_id: str | None,
        path_confidence: PathConfidence,
        technique_coverage: list[str],
        attributed_actors: list[str],
        step_count: int,
        evidence_count: int,
        max_exposure_score: float,
        first_step_at: datetime | None,
        last_step_at: datetime | None,
        now: datetime | None = None,
    ) -> AttackPath:
        computed_at = now or datetime.now(UTC)
        path = cls(
            id=id,
            organization_id=organization_id,
            root_entity_id=root_entity_id,
            root_canonical_key=root_canonical_key,
            terminal_entity_id=terminal_entity_id,
            path_confidence=path_confidence,
            technique_coverage=technique_coverage,
            attributed_actors=attributed_actors,
            step_count=step_count,
            evidence_count=evidence_count,
            max_exposure_score=max_exposure_score,
            first_step_at=first_step_at,
            last_step_at=last_step_at,
            status=PathStatus.ACTIVE,
            created_at=computed_at,
            updated_at=computed_at,
        )
        path._events.append(
            AttackPathComputed(
                path_id=id,
                organization_id=organization_id,
                root_entity_id=root_entity_id,
                step_count=step_count,
                path_confidence=path_confidence.value,
                computed_at=computed_at,
            )
        )
        return path

    @property
    def id(self) -> str:
        return self._id

    @property
    def organization_id(self) -> str:
        return self._organization_id

    @property
    def root_entity_id(self) -> str:
        return self._root_entity_id

    @property
    def root_canonical_key(self) -> str:
        return self._root_canonical_key

    @property
    def terminal_entity_id(self) -> str | None:
        return self._terminal_entity_id

    @property
    def path_confidence(self) -> PathConfidence:
        return self._path_confidence

    @property
    def technique_coverage(self) -> tuple[str, ...]:
        return tuple(self._technique_coverage)

    @property
    def attributed_actors(self) -> tuple[str, ...]:
        return tuple(self._attributed_actors)

    @property
    def step_count(self) -> int:
        return self._step_count

    @property
    def evidence_count(self) -> int:
        return self._evidence_count

    @property
    def max_exposure_score(self) -> float:
        return self._max_exposure_score

    @property
    def first_step_at(self) -> datetime | None:
        return self._first_step_at

    @property
    def last_step_at(self) -> datetime | None:
        return self._last_step_at

    @property
    def status(self) -> PathStatus:
        return self._status

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def updated_at(self) -> datetime:
        return self._updated_at

    def collect_events(self) -> list[AttackPathDomainEvent]:
        events = list(self._events)
        self._events.clear()
        return events

    def contain(self, *, now: datetime | None = None) -> None:
        self._transition(PathStatus.CONTAINED, now or datetime.now(UTC))

    def archive(self, *, now: datetime | None = None) -> None:
        self._transition(PathStatus.HISTORICAL, now or datetime.now(UTC))

    def _transition(self, to: PathStatus, when: datetime) -> None:
        allowed = _ALLOWED.get(self._status, frozenset())
        if to not in allowed:
            raise InvalidPathStatusTransitionError(self._status.value, to.value)
        previous = self._status
        self._status = to
        self._updated_at = when
        self._events.append(
            AttackPathUpdated(
                path_id=self._id,
                organization_id=self._organization_id,
                from_status=previous.value,
                to_status=to.value,
                updated_at=when,
            )
        )
