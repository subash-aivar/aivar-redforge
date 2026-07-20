"""ProjectionPublisher — append-only event history for red-team projection replay."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from redforge.domain.platform.events import EventEnvelope, make_envelope


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class ProjectionEventRecord:
    envelope: EventEnvelope
    domain_event: Any


@dataclass(frozen=True, slots=True)
class ReplayResult:
    events_replayed: int
    from_position: int
    to_position: int
    organization_id: str | None
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "events_replayed": self.events_replayed,
            "from_position": self.from_position,
            "to_position": self.to_position,
            "organization_id": self.organization_id,
            "details": dict(self.details),
        }


class ProjectionPublisher:
    """Append-only in-process event log for red-team projection replay."""

    PROJECTION_SCHEMA_VERSION = 1

    def __init__(self) -> None:
        self._log: list[ProjectionEventRecord] = []
        self._global_position = 0
        self._stream_positions: dict[str, int] = {}

    @property
    def version(self) -> int:
        return self.PROJECTION_SCHEMA_VERSION

    def _tenant_of(self, event: Any) -> str:
        tid = getattr(event, "tenant_id", None)
        if tid is None:
            return str(getattr(event, "organization_id", "") or "")
        if hasattr(tid, "value"):
            return str(tid.value)
        return str(tid)

    def publish(self, event: Any) -> EventEnvelope:
        org = self._tenant_of(event)
        aggregate_type = str(getattr(event, "aggregate_type", type(event).__name__))
        aggregate_id = str(getattr(event, "aggregate_id", "unknown"))
        stream_id = f"red_team:{org}:{aggregate_type}:{aggregate_id}"
        stream_pos = self._stream_positions.get(stream_id, 0) + 1
        self._stream_positions[stream_id] = stream_pos
        self._global_position += 1
        event_type = f"red_team.{type(event).__name__}"
        occurred_at = getattr(event, "occurred_at", _utc_now())
        base = make_envelope(
            payload=event,
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            stream_id=stream_id,
            organization_id=org,
            occurred_at=occurred_at,
        )
        envelope = EventEnvelope(
            event_id=str(getattr(event, "event_id", base.event_id)),
            stream_id=stream_id,
            stream_position=stream_pos,
            global_position=self._global_position,
            event_type=event_type,
            aggregate_type=aggregate_type,
            aggregate_id=aggregate_id,
            organization_id=org,
            payload=event,
            metadata=base.metadata,
            occurred_at=occurred_at,
            recorded_at=_utc_now(),
        )
        self._log.append(ProjectionEventRecord(envelope=envelope, domain_event=event))
        return envelope

    def publish_batch(self, events: list[Any]) -> list[EventEnvelope]:
        return [self.publish(e) for e in events]

    def history(
        self,
        *,
        organization_id: str | None = None,
        from_position: int = 0,
    ) -> list[ProjectionEventRecord]:
        records = self._log
        if organization_id is not None:
            records = [
                r for r in records if r.envelope.organization_id == organization_id
            ]
        return [r for r in records if r.envelope.global_position >= from_position]

    def clear(self) -> None:
        self._log.clear()
        self._global_position = 0
        self._stream_positions.clear()

    def status(self) -> dict[str, Any]:
        return {
            "schema_version": self.PROJECTION_SCHEMA_VERSION,
            "global_position": self._global_position,
            "event_count": len(self._log),
            "stream_count": len(self._stream_positions),
        }
