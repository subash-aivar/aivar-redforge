"""UUID identity value objects for the campaign domain."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import uuid7

if TYPE_CHECKING:
    from uuid import UUID




from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
# Phase 1 convergence: no local UUID-backed TenantId type.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class CampaignId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("CampaignId must not be nil UUID")

    @classmethod
    def generate(cls) -> CampaignId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class CampaignInstanceId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("CampaignInstanceId must not be nil UUID")

    @classmethod
    def generate(cls) -> CampaignInstanceId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class CampaignObjectiveId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("CampaignObjectiveId must not be nil UUID")

    @classmethod
    def generate(cls) -> CampaignObjectiveId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class CampaignApprovalId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("CampaignApprovalId must not be nil UUID")

    @classmethod
    def generate(cls) -> CampaignApprovalId:
        return cls(uuid7())

    def __str__(self) -> str:
        return str(self.value)
