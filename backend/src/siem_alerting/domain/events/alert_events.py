"""Domain events produced by siem_alerting (M37 §2.4).

Per M41 ADR-G3, the lifecycle-start event below is implemented under
the canonical cross-domain name `SIEMFindingOpened` starting at M42
Phase 8 (where `siem_alerting`'s application layer wires it into the
event dispatcher and `incident`'s subscription). This Phase 1 domain
layer keeps M37's original event name (`AlertRaised`) since Phase 8 is
explicitly where the ADR-G3 rename is applied — this docstring exists
so Phase 8 doesn't have to rediscover that mapping.
"""

from __future__ import annotations

from dataclasses import dataclass

from siem_alerting.domain.events.base import BaseDomainEvent
from siem_alerting.domain.value_objects.enums import AlertSeverity


@dataclass(frozen=True, slots=True)
class AlertRaised(BaseDomainEvent):
    """M41 ADR-G3: cross-domain canonical name is `SIEMFindingOpened`."""

    dedup_key: str = ""
    severity: AlertSeverity = AlertSeverity.LOW


@dataclass(frozen=True, slots=True)
class AlertDeduplicated(BaseDomainEvent):
    dedup_key: str = ""
    original_alert_id: str = ""


@dataclass(frozen=True, slots=True)
class AlertSuppressed(BaseDomainEvent):
    suppression_reason: str = ""


@dataclass(frozen=True, slots=True)
class AlertEscalated(BaseDomainEvent):
    severity: AlertSeverity = AlertSeverity.LOW


@dataclass(frozen=True, slots=True)
class AlertAcknowledged(BaseDomainEvent):
    acknowledged_by: str = ""


@dataclass(frozen=True, slots=True)
class AlertClosed(BaseDomainEvent):
    closed_by: str = ""
    resolution: str = ""
