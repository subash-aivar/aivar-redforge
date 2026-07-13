"""Protocol contracts and input DTOs for the AI Asset & Inventory platform.

All collaborators are @runtime_checkable Protocols. The application
layer depends only on these abstractions; infrastructure implements them.

DiscoveredAssetInput is the clean boundary between discovery adapters
and the inventory pipeline. The pipeline depends only on this DTO.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.inventory.entity import AIAsset
    from redforge.domain.inventory.value_objects import (
        AssetDependencyRef,
        AssetFingerprint,
        AssetRelationship,
        InventorySnapshot,
    )


# ─── Input DTOs ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class DiscoveredAssetInput:
    """Canonical input DTO produced by discovery adapters.

    Discovery adapters (API, config, scan) produce these DTOs.
    The inventory pipeline normalizes, fingerprints, and persists them.
    """

    name: str
    asset_type: str                             # AssetType.value
    external_id: str                            # source-system identifier
    discovery_source: str                       # AssetDiscoverySource.value
    organization_id: str
    description: str = ""
    fingerprint_fields: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, str] = field(default_factory=dict)
    dependency_external_ids: tuple[str, ...] = ()    # external IDs this asset depends on
    relationship_hints: tuple[tuple[str, str], ...] = ()  # (target_ext_id, rel_type)


@dataclass(frozen=True)
class InventoryContext:
    """Everything the inventory service needs for one pipeline run.

    existing_assets: assets already in the repository for this org
        (used for fingerprint comparison and deduplication).
    """

    organization_id: str
    discovered: tuple[DiscoveredAssetInput, ...]
    period_label: str = ""          # human label for this run, e.g. "2026-07-09"


@dataclass(frozen=True)
class NormalizedAssetInput:
    """Output of the normalization phase — validated, cleaned DiscoveredAssetInput."""

    name: str
    asset_type: str
    external_id: str
    discovery_source: str
    organization_id: str
    description: str
    fingerprint_fields: dict[str, str]
    metadata: dict[str, str]
    dependency_external_ids: tuple[str, ...]
    relationship_hints: tuple[tuple[str, str], ...]


# ─── Protocol Ports ───────────────────────────────────────────────────────────


@runtime_checkable
class AssetNormalizerPort(Protocol):
    """Normalizes raw discovered asset inputs into clean, validated records."""

    def normalize(
        self, inputs: list[DiscoveredAssetInput]
    ) -> list[NormalizedAssetInput]: ...


@runtime_checkable
class AssetFingerprintPort(Protocol):
    """Computes and compares asset fingerprints."""

    def compute(self, fields: dict[str, str]) -> AssetFingerprint: ...

    def has_changed(
        self,
        existing: AssetFingerprint,
        new_fields: dict[str, str],
    ) -> bool: ...


@runtime_checkable
class DependencyResolverPort(Protocol):
    """Resolves dependency references and detects cycles."""

    def resolve(
        self,
        assets: list[AIAsset],
        inputs: list[NormalizedAssetInput],
    ) -> list[AssetDependencyRef]: ...

    def has_cycle(
        self,
        assets: list[AIAsset],
        candidate_dep_id: str,
        from_asset_id: str,
    ) -> bool: ...


@runtime_checkable
class RelationshipResolverPort(Protocol):
    """Resolves typed relationships between assets."""

    def resolve(
        self,
        assets: list[AIAsset],
        inputs: list[NormalizedAssetInput],
    ) -> list[tuple[str, AssetRelationship]]: ...

    def infer_relationships(
        self,
        assets: list[AIAsset],
    ) -> list[tuple[str, AssetRelationship]]: ...


@runtime_checkable
class AssetRepositoryPort(Protocol):
    """Persistence port for AIAsset aggregates."""

    async def save(self, asset: AIAsset) -> None: ...

    async def get_by_id(self, asset_id: str) -> AIAsset | None: ...

    async def get_by_external_id(
        self, organization_id: str, external_id: str
    ) -> AIAsset | None: ...

    async def list_for_org(
        self,
        organization_id: str,
        asset_type: str | None = None,
        lifecycle_stage: str | None = None,
    ) -> list[AIAsset]: ...

    async def delete(self, asset_id: str) -> None: ...


@runtime_checkable
class InventorySnapshotPort(Protocol):
    """Stores and retrieves inventory snapshots."""

    async def save(self, snapshot: InventorySnapshot) -> None: ...

    async def get_latest(
        self, organization_id: str
    ) -> InventorySnapshot | None: ...

    async def list_for_org(
        self, organization_id: str, limit: int = 10
    ) -> list[InventorySnapshot]: ...


@runtime_checkable
class InventoryProjectorPort(Protocol):
    """Projects inventory state into the knowledge graph."""

    def project_asset(self, asset: AIAsset) -> None: ...

    def project_relationship(
        self, source_asset: AIAsset, relationship: AssetRelationship
    ) -> None: ...

    def project_snapshot(self, snapshot: InventorySnapshot) -> None: ...
