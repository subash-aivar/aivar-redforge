"""Application queries for threat_report_intel."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from threat_report_intel.application.exceptions import ApplicationValidationError

if TYPE_CHECKING:
    from threat_report_intel.domain.value_objects.identifiers import TenantId

DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200


@dataclass(frozen=True, slots=True)
class GetThreatReportQuery:
    tenant_id: TenantId | None
    threat_report_id: str


@dataclass(frozen=True, slots=True)
class ListThreatReportsQuery:
    tenant_id: TenantId | None
    lifecycle_status: str | None = None
    severity: str | None = None
    tlp_marking: str | None = None
    limit: int = DEFAULT_LIST_LIMIT
    offset: int = 0

    def __post_init__(self) -> None:
        if not (1 <= self.limit <= MAX_LIST_LIMIT):
            raise ApplicationValidationError(
                f"limit must be in [1, {MAX_LIST_LIMIT}], got {self.limit!r}"
            )
        if self.offset < 0:
            raise ApplicationValidationError(f"offset must be >= 0, got {self.offset!r}")
