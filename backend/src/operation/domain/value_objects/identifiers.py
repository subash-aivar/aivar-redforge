"""UUID identity value objects for the operation domain."""

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
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("OperationId must not be nil UUID")

    @classmethod
    def generate(cls) -> OperationId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ExecutionPlanVersionId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("ExecutionPlanVersionId must not be nil UUID")

    @classmethod
    def generate(cls) -> ExecutionPlanVersionId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ExecutionStepId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("ExecutionStepId must not be nil UUID")

    @classmethod
    def generate(cls) -> ExecutionStepId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class OperationApprovalId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("OperationApprovalId must not be nil UUID")

    @classmethod
    def generate(cls) -> OperationApprovalId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class OperationObjectiveId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("OperationObjectiveId must not be nil UUID")

    @classmethod
    def generate(cls) -> OperationObjectiveId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class StepDependencyId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("StepDependencyId must not be nil UUID")

    @classmethod
    def generate(cls) -> StepDependencyId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)
