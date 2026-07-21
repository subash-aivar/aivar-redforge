"""Identity value objects for exposure."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ExposureRecordId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> ExposureRecordId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class RiskAmplifierId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> RiskAmplifierId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class ExposureScoreSnapshotId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> ExposureScoreSnapshotId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class AmplifierWeightConfigurationId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> AmplifierWeightConfigurationId:
        return cls(uuid4())
