"""Ingestion source reference — the provisional, Phase-1 shape of what
M37 §2.1 later formalizes as `EventSource` inside the CEM (M42 Phase 2).

Kept local to `siem_ingestion` rather than in `siem_shared` because
Phase 1 explicitly precedes the CEM: `IngestedEventBatch` only needs to
know *where a batch came from*, not the full normalized event shape.
"""

from __future__ import annotations

from dataclasses import dataclass

from redforge.shared.identifiers import EntityId
from siem_ingestion.domain.value_objects.enums import IngestionSourceType


@dataclass(frozen=True, slots=True)
class IngestionSourceRef:
    source_type: IngestionSourceType
    vendor: str
    source_connector_id: EntityId | None = None

    def __post_init__(self) -> None:
        if not self.vendor.strip():
            raise ValueError("IngestionSourceRef.vendor must be a non-empty string")
        if self.source_type == IngestionSourceType.CONNECTOR and self.source_connector_id is None:
            raise ValueError(
                "IngestionSourceRef.source_connector_id is required for connector-shaped sources"
            )
