"""EventSeverity — the source-reported severity/priority hint carried by
a CanonicalEvent, when the originating source provides one (e.g. a
syslog priority, a CloudTrail severity field).

This is distinct from `siem_alerting.AlertSeverity` (M43A): that field
is the platform's own computed severity for a raised `Alert`, decided
by detection/correlation logic downstream of the CEM. `EventSeverity`
here is raw, source-asserted, and optional — never authoritative on its
own, exactly the same "reference, don't duplicate" relationship the CEM
already has with Risk Engine's own scoring (M37 §11).
"""

from __future__ import annotations

from enum import StrEnum


class EventSeverity(StrEnum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
