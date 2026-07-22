from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from integration_hub.domain.value_objects.enums import ConnectorFailureMode


@dataclass(frozen=True, slots=True)
class ConnectorActionResult:
    success: bool
    failure_mode: ConnectorFailureMode | None
    external_reference: str | None
    response_payload: dict[str, object]
    executed_at: datetime
    duration_ms: int
    rollback_available: bool
    rollback_parameters: dict[str, object]
