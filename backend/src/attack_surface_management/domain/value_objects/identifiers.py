"""Typed identifiers for attack_surface_management (M49A).

`TenantId` reuses the shared platform `EntityId` (ULID-backed) per
ADR-0005 — the same pattern `risk_engine`, `vulnerability_engine`, and
`ai_posture` use — rather than duplicating it. Local aggregate/entity
identifiers are UUID-backed, consistent with `risk_engine`'s
`RiskProfileId`/`CorrelationSetId`."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class AssetId:
    value: UUID

    @classmethod
    def generate(cls) -> AssetId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class NetworkRangeId:
    value: UUID

    @classmethod
    def generate(cls) -> NetworkRangeId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class PortId:
    value: UUID

    @classmethod
    def generate(cls) -> PortId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class CertificateId:
    value: UUID

    @classmethod
    def generate(cls) -> CertificateId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class DnsRecordId:
    value: UUID

    @classmethod
    def generate(cls) -> DnsRecordId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
