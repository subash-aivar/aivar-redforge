"""RuntimeOperationsService — M15.

A normalized, client-facing read over the EXISTING runtime health
engine (`application/platform/health_engine.py`/`dynamic_health.py`,
unchanged since Sprint 26). Always live-computed — never reads the M15
transition-dedup bookkeeping table (`runtime_component_health_state`),
which exists purely to drive the separate transition-detection worker,
not to answer "what's healthy right now."
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.security_operations.value_objects import RuntimeComponentStatus

if TYPE_CHECKING:
    from redforge.application.platform.health_engine import RuntimeHealthEngine

_KNOWN_STATUSES = frozenset(
    s.value for s in RuntimeComponentStatus if s != RuntimeComponentStatus.UNKNOWN
)


@dataclass(frozen=True, slots=True)
class RuntimeComponentViewDTO:
    component_id: str
    status: str
    message: str
    checked_at: str


def _safe_status(raw: str) -> str:
    return raw if raw in _KNOWN_STATUSES else str(RuntimeComponentStatus.UNKNOWN)


class RuntimeOperationsService:
    def __init__(self, health_engine: RuntimeHealthEngine) -> None:
        self._health_engine = health_engine

    async def list_components(self) -> list[RuntimeComponentViewDTO]:
        aggregated = await self._health_engine.aggregate_health()
        return [
            RuntimeComponentViewDTO(
                component_id=c.component_id, status=_safe_status(str(c.status)),
                message=c.message, checked_at=c.checked_at.isoformat(),
            )
            for c in aggregated.components
        ]

    async def unhealthy_count(self) -> int:
        aggregated = await self._health_engine.aggregate_health()
        return sum(1 for c in aggregated.components if str(c.status) == "unhealthy")
