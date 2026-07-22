from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class CandidateId:
    value: UUID

    @classmethod
    def generate(cls) -> CandidateId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AnomalySignalRef:
    signal_id: str
    source: str


@dataclass(frozen=True, slots=True)
class AttckTechniqueRef:
    technique_id: str
    name: str
