"""campaignexecution identifier value objects."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid7


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> TenantId:
        return cls(uuid7())


@dataclass(frozen=True, slots=True)
class TaskGraphExecutionId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> TaskGraphExecutionId:
        return cls(uuid7())


@dataclass(frozen=True, slots=True)
class SafetyMonitorId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> SafetyMonitorId:
        return cls(uuid7())


@dataclass(frozen=True, slots=True)
class TaskExecutionRecordId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> TaskExecutionRecordId:
        return cls(uuid7())


@dataclass(frozen=True, slots=True)
class CampaignInstanceId:
    """Reference to a campaign instance (owned by campaign context)."""

    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class CampaignTaskId:
    """Reference to a task in the task graph (owned by taskgraph context)."""

    value: UUID

    def __str__(self) -> str:
        return str(self.value)
