from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
# Phase 1 convergence: no local UUID-backed TenantId type.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class AISystemAssetId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AgentOperationalEnvelopeId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> AgentOperationalEnvelopeId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class AgentDeviationEventId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> AgentDeviationEventId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class AuthorizedActionId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> AuthorizedActionId:
        return cls(uuid4())
