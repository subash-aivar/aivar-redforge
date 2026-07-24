"""EventSource — a CanonicalEvent's provenance (M37 §2.1): the *canonical*
shape, distinct from `siem_ingestion.IngestionSourceRef`'s Phase-1
provisional envelope (M43A), which predated the CEM by design (M42
Phase 3's own dependency note: ingestion's batch envelope references
the eventual schema version, not the full CEM shape). Reconciling
`siem_ingestion`'s provisional type with this canonical one is explicit
M42 Phase 3 work, out of scope for this CEM-only milestone.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from siem_shared.domain.exceptions.domain_exceptions import (
    EmptyVendorError,
    MissingConnectorIdError,
)

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId


class EventSourceType(StrEnum):
    CONNECTOR = "connector"
    AGENT = "agent"
    CLOUD = "cloud"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    IDENTITY = "identity"
    AI = "ai"
    CUSTOM = "custom"


@dataclass(frozen=True, slots=True)
class EventSource:
    source_type: EventSourceType
    vendor: str
    source_connector_id: EntityId | None = None

    def __post_init__(self) -> None:
        if not self.vendor.strip():
            raise EmptyVendorError()
        if self.source_type == EventSourceType.CONNECTOR and self.source_connector_id is None:
            raise MissingConnectorIdError()
