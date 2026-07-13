"""SQLAlchemy repository for the AIAsset aggregate — M3.

Implements `AssetRepositoryPort` (application/inventory/contracts.py).
Serializes the full nested value-object graph (fingerprint, version
history, owner, metadata, dependencies, relationships) to/from the
`data` JSON column; the relational columns
(organization_id/asset_type/external_id/discovery_source/
lifecycle_stage) are kept in sync for tenant-scoped query/uniqueness.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from redforge.domain.inventory.entity import AIAsset
from redforge.domain.inventory.value_objects import (
    AssetDependencyRef,
    AssetDiscoverySource,
    AssetFingerprint,
    AssetHealthMetrics,
    AssetHealthStatus,
    AssetLifecycleStage,
    AssetMetadata,
    AssetOwner,
    AssetRelationship,
    AssetRelationshipType,
    AssetType,
    AssetVersion,
)
from redforge.infrastructure.database.models.asset_connector import AIAssetModel
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _ensure_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _asset_to_data(asset: AIAsset) -> dict[str, Any]:
    return {
        "fingerprint": {
            "fingerprint_hash": asset.fingerprint.fingerprint_hash,
            "fingerprint_data": asset.fingerprint.fingerprint_data,
            "algorithm": asset.fingerprint.algorithm,
        },
        "version_history": [
            {
                "version_tag": v.version_tag,
                "fingerprint_hash": v.fingerprint_hash,
                "recorded_at_iso": v.recorded_at_iso,
                "change_summary": v.change_summary,
            }
            for v in asset.version_history
        ],
        "owner": (
            {
                "owner_id": asset.owner.owner_id,
                "owner_name": asset.owner.owner_name,
                "owner_type": asset.owner.owner_type,
                "contact_email": asset.owner.contact_email,
            }
            if asset.owner
            else None
        ),
        "metadata": dict(asset.metadata.entries),
        "dependencies": [
            {
                "dependency_id": d.dependency_id,
                "relationship_type": d.relationship_type.value,
                "is_required": d.is_required,
                "metadata": list(d.metadata),
            }
            for d in asset.dependencies
        ],
        "relationships": [
            {
                "relationship_id": r.relationship_id,
                "target_asset_id": r.target_asset_id,
                "relationship_type": r.relationship_type.value,
                "label": r.label,
                "metadata": list(r.metadata),
            }
            for r in asset.relationships
        ],
        "health_status": asset.health_status.value,
        "health_metrics": (
            {
                "last_checked_at_iso": asset.health_metrics.last_checked_at_iso,
                "latency_ms": asset.health_metrics.latency_ms,
                "error_rate": asset.health_metrics.error_rate,
                "availability_pct": asset.health_metrics.availability_pct,
                "notes": asset.health_metrics.notes,
            }
            if asset.health_metrics
            else None
        ),
        "description": asset.description,
    }


def _model_to_asset(model: AIAssetModel) -> AIAsset:
    data = model.data
    fp_data = data["fingerprint"]
    fingerprint = AssetFingerprint(
        fingerprint_hash=fp_data["fingerprint_hash"],
        fingerprint_data=fp_data["fingerprint_data"],
        algorithm=fp_data.get("algorithm", "sha256"),
    )
    version_history = tuple(
        AssetVersion(
            version_tag=v["version_tag"],
            fingerprint_hash=v["fingerprint_hash"],
            recorded_at_iso=v["recorded_at_iso"],
            change_summary=v.get("change_summary", ""),
        )
        for v in data.get("version_history", [])
    )
    owner_data = data.get("owner")
    owner = (
        AssetOwner(
            owner_id=owner_data["owner_id"],
            owner_name=owner_data["owner_name"],
            owner_type=owner_data.get("owner_type", "team"),
            contact_email=owner_data.get("contact_email", ""),
        )
        if owner_data
        else None
    )
    dependencies = frozenset(
        AssetDependencyRef(
            dependency_id=d["dependency_id"],
            relationship_type=AssetRelationshipType(d["relationship_type"]),
            is_required=d.get("is_required", True),
            metadata=tuple(tuple(m) for m in d.get("metadata", [])),
        )
        for d in data.get("dependencies", [])
    )
    relationships = tuple(
        AssetRelationship(
            relationship_id=r["relationship_id"],
            target_asset_id=r["target_asset_id"],
            relationship_type=AssetRelationshipType(r["relationship_type"]),
            label=r.get("label", ""),
            metadata=tuple(tuple(m) for m in r.get("metadata", [])),
        )
        for r in data.get("relationships", [])
    )
    health_metrics_data = data.get("health_metrics")
    health_metrics = (
        AssetHealthMetrics(
            last_checked_at_iso=health_metrics_data["last_checked_at_iso"],
            latency_ms=health_metrics_data.get("latency_ms", 0),
            error_rate=health_metrics_data.get("error_rate", 0.0),
            availability_pct=health_metrics_data.get("availability_pct", 100.0),
            notes=health_metrics_data.get("notes", ""),
        )
        if health_metrics_data
        else None
    )

    return AIAsset(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        asset_type=AssetType(model.asset_type),
        name=model.name,
        description=data.get("description", ""),
        external_id=model.external_id,
        discovery_source=AssetDiscoverySource(model.discovery_source),
        lifecycle_stage=AssetLifecycleStage(model.lifecycle_stage),
        health_status=AssetHealthStatus(data.get("health_status", "unknown")),
        fingerprint=fingerprint,
        version_history=version_history,
        owner=owner,
        metadata=AssetMetadata(entries=dict(data.get("metadata", {}))),
        dependencies=dependencies,
        relationships=relationships,
        health_metrics=health_metrics,
        timestamps=AuditTimestamps(
            created_at=_ensure_utc(model.created_at),
            updated_at=_ensure_utc(model.updated_at),
        ),
    )


class SqlAlchemyAssetRepository:
    """Implements `AssetRepositoryPort`. Every method is organization-scoped
    where the port signature allows — `get_by_id` additionally requires
    the caller to check `asset.organization_id` themselves (matching the
    port's existing signature), so application-layer callers MUST verify
    ownership after fetch; this repository does not silently do it for
    them since the port contract predates M3 and changing its signature
    would ripple through the existing inventory pipeline.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, asset: AIAsset) -> None:
        model = AIAssetModel(
            id=str(asset.id),
            organization_id=str(asset.organization_id),
            asset_type=asset.asset_type.value,
            name=asset.name,
            external_id=asset.external_id,
            discovery_source=asset.discovery_source.value,
            lifecycle_stage=asset.lifecycle_stage.value,
            data=_asset_to_data(asset),
            created_at=asset.timestamps.created_at,
            updated_at=asset.timestamps.updated_at,
        )
        await self._session.merge(model)
        await self._session.flush()

    async def get_by_id(self, asset_id: str) -> AIAsset | None:
        model = await self._session.get(AIAssetModel, asset_id)
        return _model_to_asset(model) if model else None

    async def get_by_id_for_org(self, asset_id: str, organization_id: str) -> AIAsset | None:
        """M3 tenant-safe accessor — verifies ownership at the query
        level (WHERE, not post-fetch filtering) so a cross-tenant lookup
        never even materializes the row.
        """
        result = await self._session.execute(
            select(AIAssetModel).where(
                AIAssetModel.id == asset_id,
                AIAssetModel.organization_id == organization_id,
            )
        )
        model = result.scalar_one_or_none()
        return _model_to_asset(model) if model else None

    async def get_by_external_id(
        self, organization_id: str, external_id: str
    ) -> AIAsset | None:
        result = await self._session.execute(
            select(AIAssetModel).where(
                AIAssetModel.organization_id == organization_id,
                AIAssetModel.external_id == external_id,
            )
        )
        model = result.scalar_one_or_none()
        return _model_to_asset(model) if model else None

    async def list_for_org(
        self,
        organization_id: str,
        asset_type: str | None = None,
        lifecycle_stage: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AIAsset]:
        stmt = select(AIAssetModel).where(AIAssetModel.organization_id == organization_id)
        if asset_type is not None:
            stmt = stmt.where(AIAssetModel.asset_type == asset_type)
        if lifecycle_stage is not None:
            stmt = stmt.where(AIAssetModel.lifecycle_stage == lifecycle_stage)
        stmt = stmt.order_by(AIAssetModel.created_at.desc()).limit(limit).offset(offset)
        result = await self._session.execute(stmt)
        return [_model_to_asset(m) for m in result.scalars().all()]

    async def delete(self, asset_id: str) -> None:
        model = await self._session.get(AIAssetModel, asset_id)
        if model is not None:
            await self._session.delete(model)
            await self._session.flush()
