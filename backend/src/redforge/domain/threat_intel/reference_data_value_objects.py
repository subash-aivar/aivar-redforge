"""Value objects for the Threat Intelligence Reference Data sub-context — M22
Phase 1 (ATT&CK Framework + CVE/KEV Foundation).

These are global, tenant-independent value objects: `TechniqueId`,
`TacticId`, and `CveId` validate the exact identifier grammar published by
MITRE ATT&CK / CVE.org, never a caller-supplied free-text string.
`EpssScore` and `CvssScore` carry their own validation so an out-of-range
probability or score can never enter the domain silently.

Enums are all StrEnum + @unique, following the exact pattern from M18/M21.
`ReferenceDataSource` is a closed provider-of-truth enum — mirrors the
existing invariant (M18's `ProviderName`) that no free-text source string
is ever persisted: a new global feed requires a new enum value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum, unique
from typing import TYPE_CHECKING

from redforge.domain.threat_intel.reference_data_exceptions import (
    InvalidCveIdError,
    InvalidCvssScoreError,
    InvalidEpssScoreError,
    InvalidTacticIdError,
    InvalidTechniqueIdError,
)

if TYPE_CHECKING:
    from datetime import date

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_TACTIC_ID_RE = re.compile(r"^TA\d{4}$")
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@unique
class ReferenceDataSource(StrEnum):
    """Closed set of global reference-data feeds. No free-text source
    string is ever persisted — a new feed requires a new enum value plus
    an ingestion path, mirroring M18's `ProviderName` invariant."""

    MITRE_ATTACK = "mitre_attack"
    CISA_KEV = "cisa_kev"
    NVD_CVE = "nvd_cve"
    EPSS_FIRST = "epss_first"


@unique
class AttackRelationshipType(StrEnum):
    """STIX 2.1 relationship types relevant to the ATT&CK technique graph.

    Only relationship types that a real MITRE ATT&CK STIX bundle produces
    between/around techniques are enumerated. Source/target objects beyond
    techniques (Groups, Software, Mitigations) are not modeled as entities
    in Phase 1 — relationships to them are still recorded via their raw
    STIX `source_ref`/`target_ref`, with `source_technique_id`/
    `target_technique_id` populated only when that side is a technique.
    """

    SUBTECHNIQUE_OF = "subtechnique-of"
    USES = "uses"
    MITIGATES = "mitigates"
    DETECTS = "detects"
    PRECEDES = "precedes"
    REVOKED_BY = "revoked-by"


@unique
class IngestionScope(StrEnum):
    """Scope of one `stix_ingestion_log` row.

    GLOBAL rows track idempotent ingestion of tenant-independent catalog
    data (ATT&CK techniques, CVE/KEV records) and always carry
    `organization_id = None`. TENANT is reserved for M22 Phase 2's
    per-organization TAXII/STIX bundle ingestion — Phase 1 never writes a
    TENANT-scoped row, but the schema is built to hold one without a
    later migration, per the Hardening Review's fix for the
    global/tenant idempotency-key conflation defect.
    """

    GLOBAL = "GLOBAL"
    TENANT = "TENANT"


@dataclass(frozen=True, slots=True)
class TechniqueId:
    """A validated MITRE ATT&CK technique identifier, e.g. `T1190` or the
    sub-technique form `T1190.001`. Never constructed from an unchecked
    string."""

    value: str

    def __post_init__(self) -> None:
        if not _TECHNIQUE_ID_RE.match(self.value):
            raise InvalidTechniqueIdError(self.value)

    @property
    def is_sub_technique(self) -> bool:
        return "." in self.value

    @property
    def parent_id(self) -> TechniqueId | None:
        """The parent technique id if this is a sub-technique, else None."""
        if not self.is_sub_technique:
            return None
        return TechniqueId(self.value.split(".", 1)[0])

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class TacticId:
    """A validated MITRE ATT&CK tactic identifier, e.g. `TA0001`."""

    value: str

    def __post_init__(self) -> None:
        if not _TACTIC_ID_RE.match(self.value):
            raise InvalidTacticIdError(self.value)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class CveId:
    """A validated CVE identifier in the CVE-YYYY-NNNN(+) format."""

    value: str

    def __post_init__(self) -> None:
        if not _CVE_ID_RE.match(self.value):
            raise InvalidCveIdError(self.value)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class EpssScore:
    """FIRST.org EPSS exploit-prediction score.

    `probability` is a 0.0-1.0 exploitation-likelihood estimate,
    `percentile` its 0.0-1.0 rank among all scored CVEs on `model_date`.
    Never a mysterious scalar — always carries the date the model that
    produced it was published, so staleness is always answerable.
    """

    probability: float
    percentile: float
    model_date: date

    def __post_init__(self) -> None:
        if not (0.0 <= self.probability <= 1.0):
            raise InvalidEpssScoreError(
                f"EPSS probability must be within [0.0, 1.0], got {self.probability!r}"
            )
        if not (0.0 <= self.percentile <= 1.0):
            raise InvalidEpssScoreError(
                f"EPSS percentile must be within [0.0, 1.0], got {self.percentile!r}"
            )


@dataclass(frozen=True, slots=True)
class CvssScore:
    """A CVSS score bound to the CVSS version that produced it and its
    full vector string, so the score is never displayed without the
    context needed to interpret it."""

    version: str  # e.g. "3.1", "2.0"
    base_score: float
    vector: str

    def __post_init__(self) -> None:
        if not (0.0 <= self.base_score <= 10.0):
            raise InvalidCvssScoreError(
                f"CVSS base score must be within [0.0, 10.0], got {self.base_score!r}"
            )
        if not self.vector or not self.vector.strip():
            raise InvalidCvssScoreError("CVSS vector must not be empty")

    @property
    def severity(self) -> str:
        """Qualitative severity band per the CVSS v3.x specification."""
        if self.base_score == 0.0:
            return "NONE"
        if self.base_score < 4.0:
            return "LOW"
        if self.base_score < 7.0:
            return "MEDIUM"
        if self.base_score < 9.0:
            return "HIGH"
        return "CRITICAL"
