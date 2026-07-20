"""Runtime source adapter protocol — raw dict / RawRuntimeEvent only (no SDKs)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Protocol

from redforge.domain.cloud_security.ports import RawRuntimeEvent


class RuntimeSourceAdapter(Protocol):
    """Yields provider payloads as raw dicts or RawRuntimeEvent wrappers."""

    def stream_events(self) -> AsyncIterator[dict[str, Any] | RawRuntimeEvent]: ...
