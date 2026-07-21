"""Typed identifiers for ai_posture."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AISystemAssetId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> AISystemAssetId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class ShadowAIAlertId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> ShadowAIAlertId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class AIThreatProfileId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> AIThreatProfileId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class AIRiskScoreSnapshotId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> AIRiskScoreSnapshotId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class AIComplianceMappingId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> AIComplianceMappingId:
        return cls(uuid4())
