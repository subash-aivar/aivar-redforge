"""Typed identifiers for incident BC."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class IncidentId:
    value: UUID

    @classmethod
    def generate(cls) -> IncidentId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ContainmentActionId:
    value: UUID

    @classmethod
    def generate(cls) -> ContainmentActionId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class EradicationVerificationId:
    value: UUID

    @classmethod
    def generate(cls) -> EradicationVerificationId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class RecoveryMilestoneId:
    value: UUID

    @classmethod
    def generate(cls) -> RecoveryMilestoneId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class CommunicationLogEntryId:
    value: UUID

    @classmethod
    def generate(cls) -> CommunicationLogEntryId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
