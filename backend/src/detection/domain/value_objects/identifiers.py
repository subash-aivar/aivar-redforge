"""UUID identity value objects for the detection domain."""

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
class DetectionRuleId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("DetectionRuleId must not be nil UUID")

    @classmethod
    def generate(cls) -> DetectionRuleId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class RuleVersionId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("RuleVersionId must not be nil UUID")

    @classmethod
    def generate(cls) -> RuleVersionId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class RuleTestCaseId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("RuleTestCaseId must not be nil UUID")

    @classmethod
    def generate(cls) -> RuleTestCaseId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class RuleTestResultId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("RuleTestResultId must not be nil UUID")

    @classmethod
    def generate(cls) -> RuleTestResultId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class MitreAttackMappingId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("MitreAttackMappingId must not be nil UUID")

    @classmethod
    def generate(cls) -> MitreAttackMappingId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class TelemetrySourceId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("TelemetrySourceId must not be nil UUID")

    @classmethod
    def generate(cls) -> TelemetrySourceId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class SimulationId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("SimulationId must not be nil UUID")

    @classmethod
    def generate(cls) -> SimulationId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class DetectionExecutionId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("DetectionExecutionId must not be nil UUID")

    @classmethod
    def generate(cls) -> DetectionExecutionId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class DetectionFindingId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("DetectionFindingId must not be nil UUID")

    @classmethod
    def generate(cls) -> DetectionFindingId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class DetectionPackId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("DetectionPackId must not be nil UUID")

    @classmethod
    def generate(cls) -> DetectionPackId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class DetectionExceptionId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("DetectionExceptionId must not be nil UUID")

    @classmethod
    def generate(cls) -> DetectionExceptionId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class DetectionEvidenceId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("DetectionEvidenceId must not be nil UUID")

    @classmethod
    def generate(cls) -> DetectionEvidenceId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class PackRuleId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("PackRuleId must not be nil UUID")

    @classmethod
    def generate(cls) -> PackRuleId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class PackVersionId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("PackVersionId must not be nil UUID")

    @classmethod
    def generate(cls) -> PackVersionId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)
