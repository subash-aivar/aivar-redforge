"""ExecutionEvent — the persisted, immediately-visible live-progress log
record for one ValidationExecution (M11).

Distinct from `entity.py`'s in-aggregate `ValidationExecutionEvent`
domain events (collected, published best-effort after commit). An
`ExecutionEvent` is written to the database the moment it happens —
that immediacy is what makes GET .../events genuine live progress for a
concurrent poller, not a replay of history after the fact. Immutable
once created: there is no update/delete operation anywhere in this
bounded context for an ExecutionEvent.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Self

from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime

    from redforge.domain.validation_execution.value_objects import ExecutionEventType


class ExecutionEvent:
    __slots__ = (
        "_event_type",
        "_execution_id",
        "_id",
        "_occurred_at",
        "_organization_id",
        "_payload",
        "_sequence",
    )

    def __init__(
        self,
        id: EntityId,
        execution_id: EntityId,
        organization_id: EntityId,
        sequence: int,
        event_type: ExecutionEventType,
        payload: dict[str, str],
        occurred_at: datetime,
    ) -> None:
        self._id = id
        self._execution_id = execution_id
        self._organization_id = organization_id
        self._sequence = sequence
        self._event_type = event_type
        self._payload = payload
        self._occurred_at = occurred_at

    @classmethod
    def create(
        cls,
        execution_id: EntityId,
        organization_id: EntityId,
        sequence: int,
        event_type: ExecutionEventType,
        payload: dict[str, str] | None = None,
    ) -> Self:
        return cls(
            id=EntityId.generate(),
            execution_id=execution_id,
            organization_id=organization_id,
            sequence=sequence,
            event_type=event_type,
            payload=payload or {},
            occurred_at=utc_now(),
        )

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def execution_id(self) -> EntityId:
        return self._execution_id

    @property
    def organization_id(self) -> EntityId:
        return self._organization_id

    @property
    def sequence(self) -> int:
        return self._sequence

    @property
    def event_type(self) -> ExecutionEventType:
        return self._event_type

    @property
    def payload(self) -> dict[str, str]:
        return dict(self._payload)

    @property
    def occurred_at(self) -> datetime:
        return self._occurred_at

    def __repr__(self) -> str:
        return (
            f"ExecutionEvent(execution={self._execution_id}, "
            f"seq={self._sequence}, type={self._event_type})"
        )
