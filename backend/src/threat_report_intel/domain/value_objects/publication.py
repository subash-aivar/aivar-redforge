"""Publication value objects — who published the report, how it is
catalogued, and what it points at. All RedForge-native and defined
locally: no cross-import of `reporting`, `analytics` or
`regulatory_notification`, which model RedForge's OWN generated
reports, analytics outputs and regulatory notifications — all unrelated
to third-party THREAT-INTELLIGENCE PUBLICATIONS."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from threat_report_intel.domain.exceptions.domain_exceptions import EmptyIdentifierError

if TYPE_CHECKING:
    from threat_report_intel.domain.value_objects.enums import TlpMarking


@dataclass(frozen=True, slots=True)
class Publisher:
    """The organization that published the report.

    Deliberately a free string, not a closed enum: vendors, CERTs,
    independent researchers and government agencies all publish threat
    intelligence, and that set never closes."""

    organization_name: str
    contact: str = ""

    def __post_init__(self) -> None:
        if not self.organization_name.strip():
            raise EmptyIdentifierError("organization_name")

    def __str__(self) -> str:
        return self.organization_name


@dataclass(frozen=True, slots=True)
class ReportMetadata:
    """Cataloguing metadata for the publication.

    `report_type` ("advisory", "analysis", "flash", "bulletin", ...) is
    free text, non-empty-validated — report taxonomies vary per
    publisher and are not RedForge's to close. `tlp_marking` IS a closed
    enum: TLP is an externally standardized, slow-moving vocabulary.
    `external_report_id` is the publisher's own tracking id and is
    genuinely optional."""

    report_type: str
    tlp_marking: TlpMarking
    external_report_id: str = ""

    def __post_init__(self) -> None:
        if not self.report_type.strip():
            raise EmptyIdentifierError("report_type")


@dataclass(frozen=True, slots=True)
class ThreatReportReference:
    """A URL or bibliographic citation the report points at (or that
    points at the report)."""

    url_or_citation: str
    description: str = ""

    def __post_init__(self) -> None:
        if not self.url_or_citation.strip():
            raise EmptyIdentifierError("url_or_citation")

    def __str__(self) -> str:
        return self.url_or_citation
