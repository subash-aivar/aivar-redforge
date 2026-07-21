"""Identity value objects for analytics."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AnalyticsDataSetId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> AnalyticsDataSetId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class SecurityKPIId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> SecurityKPIId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class AnomalyDetectionBaselineId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> AnomalyDetectionBaselineId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class AnalyticsQueryId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> AnalyticsQueryId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class QueryExecutionId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> QueryExecutionId:
        return cls(uuid4())
