"""Map finding severity / method → IncidentSeverity."""

from __future__ import annotations

from typing import ClassVar

from incident.domain.value_objects.enums import IncidentSeverity


class SeverityClassificationService:
    """IncidentSeverityClassificationService (frozen name alias)."""

    _MAP: ClassVar[dict[str, IncidentSeverity]] = {
        "critical": IncidentSeverity.P1_CRITICAL,
        "p1": IncidentSeverity.P1_CRITICAL,
        "high": IncidentSeverity.P2_HIGH,
        "p2": IncidentSeverity.P2_HIGH,
        "medium": IncidentSeverity.P3_MEDIUM,
        "p3": IncidentSeverity.P3_MEDIUM,
        "low": IncidentSeverity.P4_LOW,
        "p4": IncidentSeverity.P4_LOW,
        "info": IncidentSeverity.P4_LOW,
    }

    def from_finding_severity(self, finding_severity: str) -> IncidentSeverity:
        key = finding_severity.strip().lower()
        return self._MAP.get(key, IncidentSeverity.P3_MEDIUM)
