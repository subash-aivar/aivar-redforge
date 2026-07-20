"""In-memory FakeRuntimeSourceAdapter for unit/API tests."""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from redforge.domain.cloud_security.ports import RawRuntimeEvent


class FakeRuntimeSourceAdapter:
    """Seeds and streams generic runtime payloads without cloud SDKs."""

    def __init__(self, payloads: Sequence[dict[str, Any]] | None = None) -> None:
        self._payloads: list[dict[str, Any]] = list(payloads or [])

    def seed(self, *payloads: dict[str, Any]) -> None:
        self._payloads.extend(payloads)

    def seed_many(self, payloads: Sequence[dict[str, Any]]) -> None:
        self._payloads.extend(payloads)

    def clear(self) -> None:
        self._payloads.clear()

    @staticmethod
    def sample_event(
        *,
        source: str = "GENERIC",
        event_name: str = "TestEvent",
        event_id: str | None = None,
        principal_id: str = "user-1",
    ) -> dict[str, Any]:
        eid = event_id or str(uuid4())
        return {
            "provider": "generic",
            "source": source,
            "event_id": eid,
            "event_time": datetime.now(UTC).isoformat(),
            "event_name": event_name,
            "region": "us-east-1",
            "source_ip": "10.0.0.1",
            "user_agent": "fake-agent",
            "identity": {
                "principal_id": principal_id,
                "principal_type": "User",
                "principal_name": principal_id,
                "account_id": "111122223333",
            },
            "raw": {"event_id": eid, "event_name": event_name},
        }

    async def stream_events(self) -> AsyncIterator[dict[str, Any] | RawRuntimeEvent]:
        for payload in self._payloads:
            event_time_raw = payload.get("event_time")
            if isinstance(event_time_raw, datetime):
                event_time = event_time_raw
            elif isinstance(event_time_raw, str) and event_time_raw:
                event_time = datetime.fromisoformat(event_time_raw.replace("Z", "+00:00"))
            else:
                event_time = datetime.now(UTC)
            yield RawRuntimeEvent(
                event_id=str(payload.get("event_id") or ""),
                event_time=event_time,
                source=str(payload.get("source") or "GENERIC"),
                payload=dict(payload),
            )
