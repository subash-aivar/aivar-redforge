"""Value objects for M26 Phase 8 platform orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, unique
from typing import Self
from uuid import UUID, uuid4


@unique
class RunStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


@unique
class StepStatus(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"


@unique
class StepName(StrEnum):
    REGISTER_PROVIDER = "REGISTER_PROVIDER"
    REGISTER_ACCOUNT = "REGISTER_ACCOUNT"
    DISCOVER_ASSETS = "DISCOVER_ASSETS"
    DISCOVER_IDENTITY = "DISCOVER_IDENTITY"
    EVALUATE_CSPM = "EVALUATE_CSPM"
    DISCOVER_KUBERNETES = "DISCOVER_KUBERNETES"
    INGEST_RUNTIME = "INGEST_RUNTIME"
    CALCULATE_RISK = "CALCULATE_RISK"
    PROJECT_GRAPH = "PROJECT_GRAPH"
    VALIDATE = "VALIDATE"


@unique
class OrchestrationScope(StrEnum):
    ACCOUNT = "ACCOUNT"
    ORGANIZATION = "ORGANIZATION"
    CUSTOM = "CUSTOM"


@unique
class PackageName(StrEnum):
    FOUNDATION = "foundation"
    INVENTORY = "inventory"
    IDENTITY = "identity"
    CSPM = "cspm"
    KUBERNETES = "kubernetes"
    RUNTIME = "runtime"
    RISK = "risk"
    SECURITY_GRAPH = "security_graph"
    COMPLIANCE = "compliance"


@unique
class PackageHealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"


@dataclass(frozen=True, slots=True)
class OrchestrationRunId:
    value: UUID

    def __post_init__(self) -> None:
        if not isinstance(self.value, UUID):
            raise ValueError("OrchestrationRunId requires UUID")

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> Self:
        return cls(uuid4())

    @classmethod
    def from_str(cls, value: str) -> Self:
        return cls(UUID(value))
