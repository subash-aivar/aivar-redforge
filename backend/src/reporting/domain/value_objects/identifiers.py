"""Identity value objects for reporting."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ReportTemplateId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> ReportTemplateId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class ScheduledReportId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> ScheduledReportId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class ReportInstanceId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> ReportInstanceId:
        return cls(uuid4())
