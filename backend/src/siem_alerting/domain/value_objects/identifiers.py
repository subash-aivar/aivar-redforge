"""Typed identifiers for siem_alerting."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class AlertId:
    value: UUID

    @classmethod
    def generate(cls) -> AlertId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
