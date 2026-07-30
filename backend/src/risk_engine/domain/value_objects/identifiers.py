"""Typed identifiers for risk_engine (M48B).

`TenantId` reuses the shared platform `EntityId` (ULID-backed) per
ADR-0005 — the same pattern `vulnerability_engine` and `ai_security`
use — rather than duplicating it. `RiskProfileId`/`CorrelationSetId`
are UUID-backed local identifiers."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from redforge.shared.identifiers import EntityId
from risk_engine.domain.exceptions.domain_exceptions import EmptyIdentifierError

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class RiskProfileId:
    value: UUID

    @classmethod
    def generate(cls) -> RiskProfileId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class CorrelationSetId:
    value: UUID

    @classmethod
    def generate(cls) -> CorrelationSetId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


def _non_empty(value: str, identifier_name: str) -> str:
    if not value.strip():
        raise EmptyIdentifierError(identifier_name)
    return value
