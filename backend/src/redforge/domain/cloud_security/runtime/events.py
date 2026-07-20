"""Domain events for runtime visibility (inventory/observation only — no detections)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class RuntimeDomainEvent:
    occurred_at: datetime
    organization_id: str
    event_id: UUID


@dataclass(frozen=True, slots=True)
class RuntimeEventIngested(RuntimeDomainEvent):
    event_type: str
    source: str
    provider_event_id: str


@dataclass(frozen=True, slots=True)
class RuntimeArtifactObserved(RuntimeDomainEvent):
    artifact_id: str
    artifact_type: str
    name: str


@dataclass(frozen=True, slots=True)
class RuntimeIdentityObserved(RuntimeDomainEvent):
    principal_id: str
    principal_type: str


@dataclass(frozen=True, slots=True)
class RuntimeConnectionObserved(RuntimeDomainEvent):
    direction: str
    protocol: str
    remote_address: str


@dataclass(frozen=True, slots=True)
class RuntimeExecutionObserved(RuntimeDomainEvent):
    process_name: str
    executable_path: str


# Freeze-aligned alias
CloudRuntimeEventIngested = RuntimeEventIngested
