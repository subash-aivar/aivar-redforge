"""UUID identity value objects for the execution domain."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import uuid7

if TYPE_CHECKING:
    from uuid import UUID




from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
# Phase 1 convergence: no local UUID-backed TenantId type.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class EngagementId:
    """Cross-context reference to an engagement (UUID only — no engagement imports)."""

    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("EngagementId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class OperationId:
    """Cross-context reference to an operation (UUID only — no operation imports)."""

    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("OperationId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class KillSwitchId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("KillSwitchId must not be nil UUID")

    @classmethod
    def generate(cls) -> KillSwitchId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class RateLimitBucketId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("RateLimitBucketId must not be nil UUID")

    @classmethod
    def generate(cls) -> RateLimitBucketId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ExecutionJournalId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("ExecutionJournalId must not be nil UUID")

    @classmethod
    def generate(cls) -> ExecutionJournalId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class JournalEntryId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("JournalEntryId must not be nil UUID")

    @classmethod
    def generate(cls) -> JournalEntryId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AttackActionId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("AttackActionId must not be nil UUID")

    @classmethod
    def generate(cls) -> AttackActionId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ExecutionWorkerId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("ExecutionWorkerId must not be nil UUID")

    @classmethod
    def generate(cls) -> ExecutionWorkerId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ExecutionStepId:
    """Cross-context reference to an operation execution step."""

    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("ExecutionStepId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class OperatorId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("OperatorId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class TargetId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("TargetId must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)
