from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class RegNotificationId:
    value: UUID

    @classmethod
    def generate(cls) -> RegNotificationId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class DraftId:
    value: UUID

    @classmethod
    def generate(cls) -> DraftId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class DeadlineId:
    value: UUID

    @classmethod
    def generate(cls) -> DeadlineId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
