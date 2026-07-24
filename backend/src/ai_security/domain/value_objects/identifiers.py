"""Typed identifiers for ai_security (M47A).

`TenantId` reuses the shared platform `EntityId` (ULID-backed) per
ADR-0005 — the same pattern `cloud_security` and `vulnerability_engine`
use — rather than duplicating it. The remaining identifiers are
UUID-backed value objects local to this context."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class TargetId:
    value: UUID

    @classmethod
    def generate(cls) -> TargetId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ModelId:
    value: UUID

    @classmethod
    def generate(cls) -> ModelId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class DeploymentId:
    value: UUID

    @classmethod
    def generate(cls) -> DeploymentId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ProviderId:
    value: UUID

    @classmethod
    def generate(cls) -> ProviderId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ConversationId:
    value: UUID

    @classmethod
    def generate(cls) -> ConversationId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class PromptId:
    value: UUID

    @classmethod
    def generate(cls) -> PromptId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class PolicyId:
    value: UUID

    @classmethod
    def generate(cls) -> PolicyId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class EvaluationId:
    value: UUID

    @classmethod
    def generate(cls) -> EvaluationId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


def _non_empty(value: str, identifier_name: str) -> str:
    from ai_security.domain.exceptions.domain_exceptions import EmptyIdentifierError

    if not value.strip():
        raise EmptyIdentifierError(identifier_name)
    return value
