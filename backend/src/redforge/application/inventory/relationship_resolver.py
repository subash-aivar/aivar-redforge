"""Relationship resolver — builds typed asset relationships from discovery hints.

Resolves relationship_hints (target_external_id, relationship_type_str) from
NormalizedAssetInput into AssetRelationship value objects, matching
target_external_id against known assets in the repository.

Also applies automatic relationship inference based on asset type combinations.

No switch statements. Relationship type mapping uses a dict registry.
"""

from __future__ import annotations

from redforge.application.inventory.contracts import (
    NormalizedAssetInput,
)
from redforge.domain.inventory.value_objects import (
    AssetRelationship,
    AssetRelationshipType,
)

if False:  # TYPE_CHECKING
    from redforge.domain.inventory.entity import AIAsset

# Registry: string -> AssetRelationshipType (from discovery hint labels)
_REL_TYPE_REGISTRY: dict[str, AssetRelationshipType] = {
    t.value: t for t in AssetRelationshipType
}


def _parse_rel_type(raw: str) -> AssetRelationshipType:
    """Parse a relationship type string, falling back to CUSTOM."""
    return _REL_TYPE_REGISTRY.get(raw.lower().strip(), AssetRelationshipType.CUSTOM)


def _make_rel_id(source_id: str, rel_type: str, target_id: str) -> str:
    return f"{source_id}:{rel_type}:{target_id}"


class DefaultRelationshipResolver:
    """Resolves asset relationship hints into typed AssetRelationship objects.

    Implements RelationshipResolverPort.
    Returns list of (source_external_id, AssetRelationship) pairs.
    """

    def resolve(
        self,
        assets: list[AIAsset],
        inputs: list[NormalizedAssetInput],
    ) -> list[tuple[str, AssetRelationship]]:
        """Resolve all relationship hints.

        Returns (source_external_id, AssetRelationship) pairs.
        Caller matches source_external_id to the right AIAsset.
        """
        # Build ext_id -> asset_id index
        ext_to_id: dict[str, str] = {
            asset.external_id: str(asset.id) for asset in assets
        }

        results: list[tuple[str, AssetRelationship]] = []

        for inp in inputs:
            source_ext_id = inp.external_id

            for target_ext_id, rel_type_str in inp.relationship_hints:
                target_asset_id = ext_to_id.get(target_ext_id)
                if target_asset_id is None:
                    continue

                source_asset_id = ext_to_id.get(source_ext_id)
                if source_asset_id is None:
                    continue

                rel_type = _parse_rel_type(rel_type_str)
                rel_id = _make_rel_id(source_asset_id, rel_type.value, target_asset_id)

                rel = AssetRelationship(
                    relationship_id=rel_id,
                    target_asset_id=target_asset_id,
                    relationship_type=rel_type,
                    label=f"{inp.asset_type}->{rel_type.value}",
                )
                results.append((source_ext_id, rel))

        return results

    def infer_relationships(
        self,
        assets: list[AIAsset],
    ) -> list[tuple[str, AssetRelationship]]:
        """Infer implicit relationships from existing dependency references.

        Converts AssetDependencyRef objects to AssetRelationship edges
        for assets that already have dependencies resolved.
        """
        results: list[tuple[str, AssetRelationship]] = []
        asset_id_set = {str(a.id) for a in assets}

        for asset in assets:
            for dep in asset.dependencies:
                if dep.dependency_id not in asset_id_set:
                    continue
                rel_id = _make_rel_id(
                    str(asset.id), dep.relationship_type.value, dep.dependency_id
                )
                # Check if relationship already exists
                existing_ids = {r.relationship_id for r in asset.relationships}
                if rel_id in existing_ids:
                    continue

                rel = AssetRelationship(
                    relationship_id=rel_id,
                    target_asset_id=dep.dependency_id,
                    relationship_type=dep.relationship_type,
                    label=f"dep:{dep.relationship_type.value}",
                )
                results.append((str(asset.id), rel))

        return results
