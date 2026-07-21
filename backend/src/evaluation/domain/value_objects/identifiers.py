"""Evaluation bounded context identifier value objects."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value == UUID(int=0):
            raise ValueError("TenantId may not be the nil UUID")

    def __str__(self) -> str:
        return str(self.value)


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
