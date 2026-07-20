"""UUID identity value objects for the evidence domain."""

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
class ExecutionEvidenceId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("ExecutionEvidenceId must not be nil UUID")

    @classmethod
    def generate(cls) -> ExecutionEvidenceId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class EvidenceChainId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("EvidenceChainId must not be nil UUID")

    @classmethod
    def generate(cls) -> EvidenceChainId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AttackActionRef:
    """Cross-context reference to an attack action (UUID only)."""

    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("AttackActionRef must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class EngagementRef:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("EngagementRef must not be nil UUID")

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class OperationRef:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("OperationRef must not be nil UUID")

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
