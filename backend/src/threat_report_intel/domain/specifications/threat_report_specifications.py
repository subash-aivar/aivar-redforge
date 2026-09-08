"""Predicate specifications over `ThreatReport`. Pure, in-memory
predicates only — no query building, no persistence concerns (mirrors
`infrastructure_intel.domain.specifications.
infrastructure_specifications`)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from threat_report_intel.domain.value_objects.enums import (
    ThreatReportLifecycleStatus,
    ThreatReportSeverity,
)

if TYPE_CHECKING:
    from threat_report_intel.domain.aggregates.threat_report import ThreatReport


class ThreatReportSpecification(Protocol):
    def is_satisfied_by(self, record: ThreatReport) -> bool: ...


class IsGlobalThreatReportSpecification:
    def is_satisfied_by(self, record: ThreatReport) -> bool:
        return record.tenant_id is None


class IsTenantThreatReportSpecification:
    def is_satisfied_by(self, record: ThreatReport) -> bool:
        return record.tenant_id is not None


class ActiveThreatReportSpecification:
    """RECORD-lifecycle predicate — says nothing about whether the
    publisher still stands behind the publication."""

    def is_satisfied_by(self, record: ThreatReport) -> bool:
        return record.lifecycle_status is ThreatReportLifecycleStatus.ACTIVE


class DeprecatedOrRevokedThreatReportSpecification:
    _TERMINAL = frozenset(
        {
            ThreatReportLifecycleStatus.DEPRECATED,
            ThreatReportLifecycleStatus.REVOKED,
        }
    )

    def is_satisfied_by(self, record: ThreatReport) -> bool:
        return record.lifecycle_status in self._TERMINAL


class SupersededThreatReportSpecification:
    def is_satisfied_by(self, record: ThreatReport) -> bool:
        return record.lifecycle_status is ThreatReportLifecycleStatus.SUPERSEDED


class HighSeverityThreatReportSpecification:
    """HIGH or CRITICAL severity, as asserted about the threat the
    report DESCRIBES — never a RedForge finding severity."""

    _HIGH = frozenset({ThreatReportSeverity.HIGH, ThreatReportSeverity.CRITICAL})

    def is_satisfied_by(self, record: ThreatReport) -> bool:
        return record.severity in self._HIGH
