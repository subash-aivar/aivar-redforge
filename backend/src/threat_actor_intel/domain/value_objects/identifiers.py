"""Typed identifiers for threat_actor_intel (M51A).

`TenantId` reuses the shared platform `EntityId` (ULID-backed) per
ADR-0005 — the same pattern `risk_engine`/`attack_surface_management`/
`vulnerability`'s `scanning` sub-domain use — rather than the raw
`organization_id: str | None` scheme `redforge.domain.threat_intel`
uses (see `docs/architecture/m51/M51A_BOUNDED_CONTEXT_DECISION.md`
for why that mismatch justified a new peer bounded context instead
of reusing that module). Local aggregate identifiers are UUID-backed,
consistent with `risk_engine`'s `RiskProfileId`/`attack_surface_
management`'s `AssetId`.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class ThreatActorId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("ThreatActorId must not be nil UUID")

    @classmethod
    def generate(cls) -> ThreatActorId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ThreatActorAssociationId:
    """Identity for a `ThreatActorAssociation` (M51.1) — UUID-backed,
    consistent with `ThreatActorId`."""

    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("ThreatActorAssociationId must not be nil UUID")

    @classmethod
    def generate(cls) -> ThreatActorAssociationId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
