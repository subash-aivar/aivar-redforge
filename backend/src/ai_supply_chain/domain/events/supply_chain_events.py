"""Domain events for ai_supply_chain."""

from __future__ import annotations

from dataclasses import dataclass

from ai_supply_chain.domain.events.base import BaseDomainEvent


@dataclass(frozen=True, slots=True)
class ModelProvenanceRecorded(BaseDomainEvent):
    ai_system_asset_id: str
    model_origin: str


@dataclass(frozen=True, slots=True)
class ProvenanceChainEntryAdded(BaseDomainEvent):
    entry_id: str
    entry_kind: str
    verification_method: str | None


@dataclass(frozen=True, slots=True)
class ChecksumVerified(BaseDomainEvent):
    checksum: str
    algorithm: str
    verification_method: str


@dataclass(frozen=True, slots=True)
class ProvenanceIntegrityMismatchDetected(BaseDomainEvent):
    expected_checksum: str
    actual_checksum: str
    verification_method: str


@dataclass(frozen=True, slots=True)
class ModelBillOfMaterialsCompleted(BaseDomainEvent):
    mbom_id: str
    component_count: int


@dataclass(frozen=True, slots=True)
class ModelBillOfMaterialsComponentAdded(BaseDomainEvent):
    mbom_id: str
    component_name: str
    component_type: str


@dataclass(frozen=True, slots=True)
class AIDiscoveryScanCompleted(BaseDomainEvent):
    scan_run_id: str
    state: str
    discovered_count: int
    unmatched_count: int
    partial: bool


@dataclass(frozen=True, slots=True)
class UnmatchedAIServiceDiscovered(BaseDomainEvent):
    discovery_source: str
    cloud_account: str
    resource_identifier: str
    service_type: str
    region: str
