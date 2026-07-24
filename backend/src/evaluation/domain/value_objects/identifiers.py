"""Evaluation bounded context identifier value objects."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
# Phase 1 convergence: no local UUID-backed TenantId type.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class CampaignEvaluationId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value == UUID(int=0):
            raise ValueError("CampaignEvaluationId may not be the nil UUID")

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> CampaignEvaluationId:
        from uuid import uuid4

        return cls(value=uuid4())


@dataclass(frozen=True, slots=True)
class CampaignMetricsSnapshotId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value == UUID(int=0):
            raise ValueError("CampaignMetricsSnapshotId may not be the nil UUID")

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> CampaignMetricsSnapshotId:
        from uuid import uuid4

        return cls(value=uuid4())


@dataclass(frozen=True, slots=True)
class ObjectiveAssessmentId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value == UUID(int=0):
            raise ValueError("ObjectiveAssessmentId may not be the nil UUID")

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> ObjectiveAssessmentId:
        from uuid import uuid4

        return cls(value=uuid4())
