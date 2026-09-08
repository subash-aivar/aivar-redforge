"""Domain events emitted by the `ThreatReport` aggregate."""

from __future__ import annotations

from dataclasses import dataclass

from threat_report_intel.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class ThreatReportObserved(BaseDomainEvent):
    canonical_title: str = ""
    publisher: str = ""
    severity: str = ""
    confidence: str = ""
    tlp_marking: str = ""


@dataclass(frozen=True, slots=True)
class ReferenceAdded(BaseDomainEvent):
    url_or_citation: str = ""


@dataclass(frozen=True, slots=True)
class EvidenceCitationAdded(BaseDomainEvent):
    citation: str = ""


@dataclass(frozen=True, slots=True)
class SourceAttributionAdded(BaseDomainEvent):
    source_system: str = ""
    confidence: str = ""


@dataclass(frozen=True, slots=True)
class ThreatReportDeprecated(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class ThreatReportRevoked(BaseDomainEvent):
    pass


@dataclass(frozen=True, slots=True)
class ThreatReportSuperseded(BaseDomainEvent):
    superseded_by: str = ""


@dataclass(frozen=True, slots=True)
class ThreatReportReactivated(BaseDomainEvent):
    pass
