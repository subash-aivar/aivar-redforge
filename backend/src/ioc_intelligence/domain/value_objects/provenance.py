"""SourceAttribution — provenance for ioc_intelligence (M51.2 Phase A;
provider vocabulary reconciled in Phase A.1 R1).

Lifted, field-for-field, from `redforge.domain.threat_intel.
fusion_value_objects.SourceAttribution`'s already-proven shape (source
system, external id, content hash, observed time, weight applied,
confidence) — the exact provenance fields ADR-M51.2-01 §Provenance
requires. Defined as ioc_intelligence's own dataclass (not imported
from `redforge.domain.threat_intel`) because its `confidence` field
must be typed as this context's own `SourceConfidence`, not
`FusionConfidence` — same reasoning `fusion_value_objects.py`'s own
docstring gives for keeping `FusionConfidence` distinct from
`CorrelationConfidence`.

`source_system` is validated at the domain boundary against the
neutral shared `ProviderName` vocabulary (the same closed set
`redforge.domain.threat_intel` uses to gate egress) plus the one
explicit `IOC_INTERNAL_SOURCE_SYSTEM` sentinel for RedForge-generated
evidence — never an unconstrained string, and never a second provider
enum.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from ioc_intelligence.domain.exceptions.domain_exceptions import (
    EmptyIdentifierError,
    UnrecognizedSourceSystemError,
)
from redforge.shared.ioc_vocabulary import IOC_INTERNAL_SOURCE_SYSTEM, ProviderName

if TYPE_CHECKING:
    from datetime import datetime

    from ioc_intelligence.domain.value_objects.enums import SourceConfidence

_RECOGNIZED_SOURCE_SYSTEMS = frozenset({p.value for p in ProviderName}) | {
    IOC_INTERNAL_SOURCE_SYSTEM
}


@dataclass(frozen=True, slots=True)
class SourceAttribution:
    """One source's contribution to an IOC — provenance that travels
    with the IOC for its entire lifetime, never discarded."""

    source_system: str
    external_id: str
    content_hash: str | None
    observed_at: datetime
    weight_applied: float
    confidence: SourceConfidence
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.source_system.strip():
            raise EmptyIdentifierError("source_system")
        if self.source_system not in _RECOGNIZED_SOURCE_SYSTEMS:
            raise UnrecognizedSourceSystemError(self.source_system)
        if not self.external_id.strip():
            raise EmptyIdentifierError("external_id")
        if not (0.0 < self.weight_applied <= 1.0):
            raise ValueError(f"weight_applied must be in (0.0, 1.0], got {self.weight_applied!r}")

    @property
    def dedup_key(self) -> tuple[str, str]:
        """`(source_system, external_id)` — the tuple `duplicate source
        attribution` detection keys on (see `IOC.add_source_attribution`)."""
        return (self.source_system, self.external_id)
