from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class ModelProvenanceDTO:
    provenance_id: str
    tenant_id: str
    ai_system_asset_id: str
    model_origin: str
    integrity_status: str
    operational_status: str
    artifact_size_bytes: int
    verification_method_latest: str | None
    trust_delegation_note_latest: str
    chain_entry_count: int
    consecutive_failures: int


@dataclass(frozen=True, slots=True)
class MBOMDTO:
    mbom_id: str
    provenance_id: str
    completed: bool
    components: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class DiscoveryScanRunDTO:
    scan_run_id: str
    state: str
    partial: bool
    discovered_count: int
    unmatched_count: int
    failed_partitions: list[str] = field(default_factory=list)
    api_calls_used: int = 0
