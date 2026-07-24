from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
# Phase 1 convergence: no local UUID-backed TenantId type.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class AutomationExecutionId:
    value: UUID

    @classmethod
    def generate(cls) -> AutomationExecutionId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AutomatedActionRecordId:
    value: UUID

    @classmethod
    def generate(cls) -> AutomatedActionRecordId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class RollbackRecordId:
    value: UUID

    @classmethod
    def generate(cls) -> RollbackRecordId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
