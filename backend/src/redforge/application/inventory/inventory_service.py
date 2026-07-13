"""InventoryService — 6-phase inventory pipeline orchestrator.

Pipeline phases:
1. Normalization — validate and clean raw discovered inputs
2. Deduplication — match against existing assets by external_id
3. Fingerprint — compute/compare fingerprints, record version changes
4. Relationship resolution — resolve typed edges between assets
5. Knowledge Graph projection — project all assets and relationships
6. Snapshot — produce an InventorySnapshot for the run

The service is stateless; all dependencies are injected via constructor.
No switch statements. No duplicated business logic from domain layer.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

from redforge.application.inventory.contracts import (
    AssetFingerprintPort,
    AssetNormalizerPort,
    AssetRepositoryPort,
    DependencyResolverPort,
    DiscoveredAssetInput,
    InventoryContext,
    InventoryProjectorPort,
    InventorySnapshotPort,
    NormalizedAssetInput,
    RelationshipResolverPort,
)
from redforge.application.inventory.dependency_resolver import (
    DefaultDependencyResolver,
)
from redforge.application.inventory.fingerprint_engine import (
    DeterministicFingerprintEngine,
)
from redforge.application.inventory.normalizer import DefaultAssetNormalizer
from redforge.application.inventory.relationship_resolver import (
    DefaultRelationshipResolver,
)
from redforge.domain.inventory.entity import AIAsset
from redforge.domain.inventory.value_objects import (
    AssetDiscoverySource,
    AssetLifecycleStage,
    AssetMetadata,
    AssetType,
    InventorySnapshot,
)
from redforge.shared.identifiers import EntityId


class InventoryService:
    """6-phase inventory pipeline orchestrator.

    Injected dependencies:
    - normalizer: validates and cleans raw inputs
    - fingerprint_engine: computes/compares asset fingerprints
    - dependency_resolver: resolves dependencies and detects cycles
    - relationship_resolver: resolves typed relationships
    - projector: projects assets to the knowledge graph
    - snapshot_store: persists inventory snapshots
    - asset_repository: persists AIAsset aggregates
    """

    def __init__(
        self,
        normalizer: AssetNormalizerPort | None = None,
        fingerprint_engine: AssetFingerprintPort | None = None,
        dependency_resolver: DependencyResolverPort | None = None,
        relationship_resolver: RelationshipResolverPort | None = None,
        projector: InventoryProjectorPort | None = None,
        snapshot_store: InventorySnapshotPort | None = None,
        asset_repository: AssetRepositoryPort | None = None,
    ) -> None:
        self._normalizer: AssetNormalizerPort = (
            normalizer or DefaultAssetNormalizer()
        )
        self._fingerprint_engine: AssetFingerprintPort = (
            fingerprint_engine or DeterministicFingerprintEngine()
        )
        self._dependency_resolver: DependencyResolverPort = (
            dependency_resolver or DefaultDependencyResolver()
        )
        self._relationship_resolver: RelationshipResolverPort = (
            relationship_resolver or DefaultRelationshipResolver()
        )
        self._projector = projector
        self._snapshot_store = snapshot_store
        self._asset_repository = asset_repository
        self._org_id_cache: dict[str, EntityId] = {}

    # ─── Public pipeline entry point ──────────────────────────────────────────

    async def run_pipeline(
        self,
        context: InventoryContext,
        existing_assets: list[AIAsset] | None = None,
    ) -> InventoryPipelineResult:
        """Execute the full 6-phase inventory pipeline.

        existing_assets: pass in pre-loaded assets to avoid an async
        repository lookup (useful in tests and batch processing).
        """
        start_time = time.monotonic()

        # Phase 1: Normalize
        normalized = self._normalize(context.discovered)

        # Phase 2: Deduplication — load existing assets
        if existing_assets is None:
            if self._asset_repository is not None:
                existing_assets = await self._asset_repository.list_for_org(
                    context.organization_id
                )
            else:
                existing_assets = []

        existing_by_ext_id: dict[str, AIAsset] = {
            a.external_id: a for a in existing_assets if a.external_id
        }

        # Phase 3: Fingerprint + upsert
        new_assets: list[AIAsset] = []
        changed_assets: list[AIAsset] = []
        unchanged_assets: list[AIAsset] = []

        for inp in normalized:
            existing = existing_by_ext_id.get(inp.external_id)
            if existing is None:
                asset = self._create_asset(inp)
                new_assets.append(asset)
            else:
                changed = self._update_fingerprint_if_needed(existing, inp)
                if changed:
                    changed_assets.append(existing)
                else:
                    unchanged_assets.append(existing)

        all_assets = new_assets + changed_assets + unchanged_assets

        # Phase 4: Resolve dependencies
        deps = self._dependency_resolver.resolve(all_assets, normalized)
        _attach_dependencies(all_assets, normalized, deps)

        # Phase 5: Resolve relationships
        rel_pairs = self._relationship_resolver.resolve(all_assets, normalized)
        _attach_relationships(all_assets, rel_pairs)

        # Infer relationships from dependencies
        inferred_rels = self._relationship_resolver.infer_relationships(all_assets)
        _attach_relationships(all_assets, inferred_rels)

        # Save
        if self._asset_repository is not None:
            for asset in new_assets + changed_assets:
                await self._asset_repository.save(asset)

        # Phase 5b: Knowledge Graph projection
        if self._projector is not None:
            for asset in all_assets:
                self._projector.project_asset(asset)
                for rel in asset.relationships:
                    self._projector.project_relationship(asset, rel)

        # Phase 6: Snapshot
        elapsed = time.monotonic() - start_time
        snapshot = self._build_snapshot(
            context.organization_id,
            all_assets,
            new_assets,
            changed_assets,
            elapsed,
        )

        if self._snapshot_store is not None:
            await self._snapshot_store.save(snapshot)

        if self._projector is not None:
            self._projector.project_snapshot(snapshot)

        return InventoryPipelineResult(
            organization_id=context.organization_id,
            all_assets=all_assets,
            new_assets=new_assets,
            changed_assets=changed_assets,
            unchanged_assets=unchanged_assets,
            snapshot=snapshot,
        )

    # ─── Synchronous pipeline (for tests and non-async contexts) ──────────────

    def run_pipeline_sync(
        self,
        context: InventoryContext,
        existing_assets: list[AIAsset] | None = None,
    ) -> InventoryPipelineResult:
        """Synchronous pipeline variant — skips async repository calls."""
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(
                self.run_pipeline(context, existing_assets)
            )
        finally:
            loop.close()

    # ─── Phase implementations ────────────────────────────────────────────────

    def _resolve_org_id(self, org_str: str) -> EntityId:
        """Convert org string to EntityId, caching per-pipeline run."""
        if org_str not in self._org_id_cache:
            try:
                self._org_id_cache[org_str] = EntityId.from_string(org_str)
            except ValueError:
                self._org_id_cache[org_str] = EntityId.generate()
        return self._org_id_cache[org_str]

    def _normalize(
        self, inputs: tuple[DiscoveredAssetInput, ...]
    ) -> list[NormalizedAssetInput]:
        return self._normalizer.normalize(list(inputs))

    def _create_asset(self, inp: NormalizedAssetInput) -> AIAsset:
        try:
            asset_type = AssetType(inp.asset_type)
        except ValueError:
            asset_type = AssetType.AI_APPLICATION

        try:
            source = AssetDiscoverySource(inp.discovery_source)
        except ValueError:
            source = AssetDiscoverySource.MANUAL

        return AIAsset.discover(
            organization_id=self._resolve_org_id(inp.organization_id),
            asset_type=asset_type,
            name=inp.name,
            description=inp.description,
            fingerprint_fields=inp.fingerprint_fields,
            external_id=inp.external_id,
            discovery_source=source,
            metadata=AssetMetadata(entries=dict(inp.metadata)),
        )

    def _update_fingerprint_if_needed(
        self, asset: AIAsset, inp: NormalizedAssetInput
    ) -> bool:
        changed = self._fingerprint_engine.has_changed(
            asset.fingerprint, inp.fingerprint_fields
        )
        if changed:
            current_count = len(asset.version_history)
            asset.update_fingerprint(
                new_fingerprint_fields=inp.fingerprint_fields,
                version_tag=f"v{current_count + 1}",
                change_summary="Detected configuration drift during inventory scan",
            )
        return changed

    def _build_snapshot(
        self,
        organization_id: str,
        all_assets: list[AIAsset],
        new_assets: list[AIAsset],
        changed_assets: list[AIAsset],
        elapsed: float,
    ) -> InventorySnapshot:
        from ulid import ULID

        type_counts: dict[str, int] = {}
        rel_count = 0
        for asset in all_assets:
            key = asset.asset_type.value
            type_counts[key] = type_counts.get(key, 0) + 1
            rel_count += asset.relationship_count

        retired_assets = [
            a for a in all_assets
            if a.lifecycle_stage == AssetLifecycleStage.RETIRED
        ]

        return InventorySnapshot(
            snapshot_id=str(ULID()),
            organization_id=organization_id,
            asset_count=len(all_assets),
            asset_type_counts=type_counts,
            relationship_count=rel_count,
            new_assets=tuple(str(a.id) for a in new_assets),
            changed_assets=tuple(str(a.id) for a in changed_assets),
            retired_assets=tuple(str(a.id) for a in retired_assets),
            created_at_iso=datetime.now(UTC).isoformat(),
            period_seconds=elapsed,
        )


# ─── Pipeline result ──────────────────────────────────────────────────────────


class InventoryPipelineResult:
    """Result of one inventory pipeline run."""

    __slots__ = (
        "all_assets",
        "changed_assets",
        "new_assets",
        "organization_id",
        "snapshot",
        "unchanged_assets",
    )

    def __init__(
        self,
        organization_id: str,
        all_assets: list[AIAsset],
        new_assets: list[AIAsset],
        changed_assets: list[AIAsset],
        unchanged_assets: list[AIAsset],
        snapshot: InventorySnapshot,
    ) -> None:
        self.organization_id = organization_id
        self.all_assets = all_assets
        self.new_assets = new_assets
        self.changed_assets = changed_assets
        self.unchanged_assets = unchanged_assets
        self.snapshot = snapshot

    @property
    def total_asset_count(self) -> int:
        return len(self.all_assets)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_assets or self.changed_assets)


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _attach_dependencies(
    assets: list[AIAsset],
    inputs: Sequence[NormalizedAssetInput],
    deps: Sequence[object],
) -> None:
    """Attach resolved dependency references to their owning assets.

    The deps list contains AssetDependencyRef objects. We match them
    to their owner asset via the normalized inputs' external_id -> asset_id
    mapping.
    """
    from redforge.domain.inventory.value_objects import AssetDependencyRef as DepRef
    ext_to_asset: dict[str, AIAsset] = {a.external_id: a for a in assets}

    for inp in inputs:
        asset = ext_to_asset.get(inp.external_id)
        if asset is None:
            continue
        for dep_ext_id in inp.dependency_external_ids:
            dep_asset = ext_to_asset.get(dep_ext_id)
            if dep_asset is None:
                continue
            from redforge.application.inventory.dependency_resolver import (
                _infer_relationship_type,
            )
            rel_type = _infer_relationship_type(
                inp.asset_type, dep_asset.asset_type.value
            )
            dep_ref = DepRef(
                dependency_id=str(dep_asset.id),
                relationship_type=rel_type,
                is_required=True,
            )
            asset.add_dependency(dep_ref)


def _attach_relationships(
    assets: list[AIAsset],
    rel_pairs: Sequence[tuple[str, object]],
) -> None:
    """Attach resolved relationships to their source assets.

    rel_pairs: (source_external_id_or_asset_id, AssetRelationship)
    """
    from redforge.domain.inventory.exceptions import DuplicateRelationshipError
    from redforge.domain.inventory.value_objects import AssetRelationship as Rel

    # Build both ext_id -> asset and asset_id -> asset indexes
    ext_to_asset: dict[str, AIAsset] = {a.external_id: a for a in assets}
    id_to_asset: dict[str, AIAsset] = {str(a.id): a for a in assets}

    for source_key, rel in rel_pairs:
        asset = ext_to_asset.get(source_key) or id_to_asset.get(source_key)
        if asset is None or not isinstance(rel, Rel):
            continue
        # Check for duplicate before adding
        existing_ids = {r.relationship_id for r in asset.relationships}
        if rel.relationship_id in existing_ids:
            continue
        import contextlib
        with contextlib.suppress(DuplicateRelationshipError):
            asset.relate_to(
                target_asset_id=rel.target_asset_id,
                relationship_type=rel.relationship_type,
                label=rel.label,
                metadata=dict(rel.metadata) if rel.metadata else {},
            )
