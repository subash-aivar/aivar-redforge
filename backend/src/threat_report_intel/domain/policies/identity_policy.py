"""ThreatReportIdentityPolicy — no duplicate `canonical_title` within a
scope (`tenant_id`, or global when `tenant_id is None`).

Uniqueness is enforced on the NORMALIZED `canonical_title`, never on
the human-readable `title`: "Operation Cloud Hopper: Technical
Analysis" and "operation-cloud-hopper: technical_analysis" are the same
report recorded twice, and must collide.

The domain-layer half of the two-layer defense; see
`ThreatReportApplicationService` for the repository-existence-check
half, mirroring `infrastructure_intel`'s dedup discipline exactly."""

from __future__ import annotations

from typing import TYPE_CHECKING

from threat_report_intel.domain.exceptions.domain_exceptions import (
    DuplicateThreatReportError,
)

if TYPE_CHECKING:
    from threat_report_intel.domain.aggregates.threat_report import ThreatReport


class ThreatReportIdentityPolicy:
    @staticmethod
    def assert_no_duplicate(existing: list[ThreatReport], canonical_title: str) -> None:
        for record in existing:
            if record.canonical_title == canonical_title:
                raise DuplicateThreatReportError(canonical_title)
