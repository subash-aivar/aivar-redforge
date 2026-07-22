from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ConnectorId:
    value: UUID

    @classmethod
    def generate(cls) -> ConnectorId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ConnectorHealthRecordId:
    value: UUID

    @classmethod
    def generate(cls) -> ConnectorHealthRecordId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
