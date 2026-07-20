"""UUID identity value objects for the engagement domain."""

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
class EngagementId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("EngagementId must not be nil UUID")

    @classmethod
    def generate(cls) -> EngagementId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class TargetAuthorizationId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("TargetAuthorizationId must not be nil UUID")

    @classmethod
    def generate(cls) -> TargetAuthorizationId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class EngagementPhaseId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("EngagementPhaseId must not be nil UUID")

    @classmethod
    def generate(cls) -> EngagementPhaseId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class EngagementApprovalId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("EngagementApprovalId must not be nil UUID")

    @classmethod
    def generate(cls) -> EngagementApprovalId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class EngagementParticipantId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("EngagementParticipantId must not be nil UUID")

    @classmethod
    def generate(cls) -> EngagementParticipantId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)
