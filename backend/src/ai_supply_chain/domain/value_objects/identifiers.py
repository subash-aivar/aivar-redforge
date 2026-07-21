"""Typed identifiers for ai_supply_chain."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AISystemAssetId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ModelProvenanceId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> ModelProvenanceId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class ProvenanceChainEntryId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> ProvenanceChainEntryId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class ModelBillOfMaterialsId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> ModelBillOfMaterialsId:
        return cls(uuid4())


@dataclass(frozen=True, slots=True)
class AIDiscoveryScanRunId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)

    @classmethod
    def generate(cls) -> AIDiscoveryScanRunId:
        return cls(uuid4())
