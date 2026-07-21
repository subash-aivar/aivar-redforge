"""UUID identity value objects for the TaskGraph domain."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import uuid7

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("TenantId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class TaskGraphId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("TaskGraphId must not be nil UUID")

    @classmethod
    def generate(cls) -> TaskGraphId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class CampaignTaskId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("CampaignTaskId must not be nil UUID")

    @classmethod
    def generate(cls) -> CampaignTaskId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class TaskGroupId:
    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ValueError("TaskGroupId must not be empty")

    def __str__(self) -> str:
        return self.value
