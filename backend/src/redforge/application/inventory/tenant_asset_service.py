"""TenantAssetService — M3.

Tenant-scoped read/write entry point for the canonical asset foundation.
Wraps the existing `AIAsset` aggregate (Sprint 22) with real PostgreSQL
persistence and the M3 identity-resolution/upsert semantics — no new
asset domain model, only the persistence + tenant-boundary layer that
was previously missing.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from sqlalchemy.exc import IntegrityError

from redforge.core.exceptions import NotFoundError
from redforge.domain.inventory.entity import AIAsset
from redforge.domain.inventory.exceptions import DuplicateRelationshipError
from redforge.domain.inventory.identity import IdentityScheme, build_external_id
from redforge.domain.inventory.value_objects import (
    AssetDiscoverySource,
    AssetMetadata,
    AssetRelationshipType,
    AssetType,
)
from redforge.infrastructure.database.repositories.asset_repository import (
    SqlAlchemyAssetRepository,
)
from redforge.infrastructure.database.unit_of_work import SessionUnitOfWork
from redforge.shared.identifiers import EntityId

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


@dataclass(frozen=True, slots=True)
class AssetDTO:
    id: str
    organization_id: str
    asset_type: str
    name: str
    description: str
    external_id: str
    discovery_source: str
    lifecycle_stage: str
    health_status: str
    first_observed_at: str
    last_observed_at: str
    relationship_count: int
    associated_target_id: str | None
    metadata: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_entity(cls, asset: AIAsset) -> AssetDTO:
        # The REDFORGE_TARGET_ID identity scheme's normalized value IS
        # the associated target's ID — decoded here for display rather
        # than stored as a second redundant field.
        associated_target_id: str | None = None
        prefix = f"{IdentityScheme.REDFORGE_TARGET_ID.value}:"
        if asset.external_id.startswith(prefix):
            associated_target_id = asset.external_id[len(prefix) :]

        return cls(
            id=str(asset.id),
            organization_id=str(asset.organization_id),
            asset_type=asset.asset_type.value,
            name=asset.name,
            description=asset.description,
            external_id=asset.external_id,
            discovery_source=asset.discovery_source.value,
            lifecycle_stage=asset.lifecycle_stage.value,
            health_status=asset.health_status.value,
            first_observed_at=asset.timestamps.created_at.isoformat(),
            last_observed_at=asset.timestamps.updated_at.isoformat(),
            relationship_count=len(asset.relationships),
            associated_target_id=associated_target_id,
            metadata=dict(asset.metadata.entries),
        )


class TenantAssetService:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def list_for_org(
        self,
        organization_id: str,
        asset_type: str | None = None,
        lifecycle_stage: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AssetDTO]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyAssetRepository(uow.session)
            assets = await repo.list_for_org(
                organization_id, asset_type, lifecycle_stage, limit, offset,
            )
        return [AssetDTO.from_entity(a) for a in assets]

    async def get_for_org(self, asset_id: str, organization_id: str) -> AssetDTO:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyAssetRepository(uow.session)
            asset = await repo.get_by_id_for_org(asset_id, organization_id)
        if asset is None:
            raise NotFoundError("Asset", asset_id)
        return AssetDTO.from_entity(asset)

    async def get_relationships_for_org(
        self, asset_id: str, organization_id: str
    ) -> list[dict[str, str]]:
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyAssetRepository(uow.session)
            asset = await repo.get_by_id_for_org(asset_id, organization_id)
        if asset is None:
            raise NotFoundError("Asset", asset_id)
        return [
            {
                "relationship_id": r.relationship_id,
                "target_asset_id": r.target_asset_id,
                "relationship_type": r.relationship_type.value,
                "label": r.label,
            }
            for r in asset.relationships
        ]

    async def get_or_create_for_target(
        self,
        organization_id: str,
        target_id: str,
        target_name: str,
        target_type: str,
    ) -> AssetDTO:
        """Resolves (or creates) the canonical asset for an AITarget,
        using the REDFORGE_TARGET_ID identity scheme.

        Race-safe: two concurrent calls for the same target_id hit the
        tenant-scoped partial unique index
        (ux_ai_assets_org_external_id); the loser's IntegrityError is
        caught and the winner's row is re-fetched and returned — never
        a duplicate canonical asset, never a crash.

        DISCOVERED ASSET != AUTHORIZED ACTIVE TEST TARGET: this method
        only creates/reads inventory identity. It never grants execution
        authorization — that remains entirely owned by AITargetService/
        the campaign launch path, which already independently verifies
        target ownership via tenant.organization_id.
        """
        external_id = build_external_id(IdentityScheme.REDFORGE_TARGET_ID, target_id)

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyAssetRepository(uow.session)
            existing = await repo.get_by_external_id(organization_id, external_id)
            if existing is not None:
                await self._project_best_effort(existing)
                return AssetDTO.from_entity(existing)

            asset_type = _map_target_type_to_asset_type(target_type)
            asset = AIAsset.discover(
                organization_id=EntityId.from_string(organization_id),
                asset_type=asset_type,
                name=target_name,
                description=f"Canonical asset for AI target '{target_name}'",
                fingerprint_fields={"target_id": target_id, "target_type": target_type},
                external_id=external_id,
                discovery_source=AssetDiscoverySource.MANUAL,
                metadata=AssetMetadata(entries={"redforge_target_id": target_id}),
            )
            try:
                await repo.save(asset)
                await uow.commit()
            except IntegrityError:
                await uow.rollback()
                # Lost the race — re-fetch the winner's row in a fresh
                # transaction and return it instead of raising.
                async with SessionUnitOfWork(self._session_factory) as retry_uow:
                    retry_repo = SqlAlchemyAssetRepository(retry_uow.session)
                    winner = await retry_repo.get_by_external_id(organization_id, external_id)
                if winner is None:  # pragma: no cover - should be unreachable
                    raise
                await self._project_best_effort(winner)
                return AssetDTO.from_entity(winner)

        await self._project_best_effort(asset)
        return AssetDTO.from_entity(asset)

    async def resolve_asset(
        self,
        organization_id: str,
        asset_type: AssetType,
        scheme: IdentityScheme,
        raw_external_id: str,
        name: str,
        description: str,
        discovery_source: AssetDiscoverySource,
        fingerprint_fields: dict[str, str] | None = None,
        metadata_entries: dict[str, str] | None = None,
    ) -> AssetDTO:
        """Generic race-safe get-or-create for any (scheme, external_id)
        pair — the same identity-resolution pattern as
        `get_or_create_for_target`, generalized for M6 network assets
        (HOST/IP_ADDRESS/NETWORK/DEVICE/SERVICE) so they reuse this one
        canonical asset aggregate rather than a disconnected network
        inventory."""
        external_id = build_external_id(scheme, raw_external_id)

        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyAssetRepository(uow.session)
            existing = await repo.get_by_external_id(organization_id, external_id)
            if existing is not None:
                await self._project_best_effort(existing)
                return AssetDTO.from_entity(existing)

            asset = AIAsset.discover(
                organization_id=EntityId.from_string(organization_id),
                asset_type=asset_type,
                name=name,
                description=description,
                fingerprint_fields=fingerprint_fields or {},
                external_id=external_id,
                discovery_source=discovery_source,
                metadata=AssetMetadata(entries=metadata_entries or {}),
            )
            try:
                await repo.save(asset)
                await uow.commit()
            except IntegrityError:
                await uow.rollback()
                async with SessionUnitOfWork(self._session_factory) as retry_uow:
                    retry_repo = SqlAlchemyAssetRepository(retry_uow.session)
                    winner = await retry_repo.get_by_external_id(organization_id, external_id)
                if winner is None:  # pragma: no cover - should be unreachable
                    raise
                await self._project_best_effort(winner)
                return AssetDTO.from_entity(winner)

        await self._project_best_effort(asset)
        return AssetDTO.from_entity(asset)

    async def update_metadata_for_org(
        self, organization_id: str, asset_id: str, metadata_entries: dict[str, str],
    ) -> AssetDTO:
        """Enriches an EXISTING asset's bounded, schemaless metadata bag
        (M13) — `resolve_asset()` only ever sets metadata at CREATION
        time; this is the missing write path for re-observing richer
        facts about an asset that already exists (e.g. a validated
        protocol) without re-creating it or touching its identity.

        Idempotent by construction: `AssetMetadata.with_entry()` simply
        overwrites the same keys with the same values on every repeat
        call — a second identical call converges to the same state, it
        never appends or duplicates. Never mutates `external_id` or any
        other identity-bearing field; version strings, banners, and
        certificate subjects belong here, never in the identity scheme.
        """
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyAssetRepository(uow.session)
            asset = await repo.get_by_id_for_org(asset_id, organization_id)
            if asset is None:
                raise NotFoundError("Asset", asset_id)
            for key, value in metadata_entries.items():
                asset.update_metadata(key, value)
            await repo.save(asset)
            await uow.commit()
        return AssetDTO.from_entity(asset)

    async def add_relationship_for_org(
        self,
        organization_id: str,
        source_asset_id: str,
        target_asset_id: str,
        relationship_type: AssetRelationshipType,
        label: str = "",
    ) -> None:
        """Idempotent: a duplicate observation of the same relationship
        is a no-op, never a raised error and never a second row."""
        async with SessionUnitOfWork(self._session_factory) as uow:
            repo = SqlAlchemyAssetRepository(uow.session)
            asset = await repo.get_by_id_for_org(source_asset_id, organization_id)
            if asset is None:
                raise NotFoundError("Asset", source_asset_id)
            try:
                asset.relate_to(target_asset_id, relationship_type, label=label)
            except DuplicateRelationshipError:
                return
            await repo.save(asset)
            await uow.commit()

        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:
                from redforge.application.security_graph import projector as sg_projector
                from redforge.infrastructure.database.repositories import (
                    security_graph_repository as sg_repo,
                )

                repo2 = sg_repo.SecurityGraphRepository(graph_uow.session)
                projector = sg_projector.SecurityGraphProjector(repo2)
                await projector.project_asset_relationship(
                    organization_id=organization_id,
                    source_asset_id=source_asset_id,
                    target_asset_id=target_asset_id,
                    relationship_type=relationship_type.value,
                )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: relationship projection failed (source=%s target=%s)",
                source_asset_id, target_asset_id, exc_info=True,
            )

    async def _project_best_effort(self, asset: AIAsset) -> None:
        """Best-effort Security Graph node/edge projection — a failure
        here is logged and never blocks or rolls back the canonical
        asset write (see security_graph/projector.py's module
        docstring)."""
        try:
            async with SessionUnitOfWork(self._session_factory) as graph_uow:
                from redforge.application.security_graph import projector as sg_projector
                from redforge.infrastructure.database.repositories import (
                    security_graph_repository as sg_repo,
                )

                repo = sg_repo.SecurityGraphRepository(graph_uow.session)
                projector = sg_projector.SecurityGraphProjector(repo)
                await projector.project_asset(
                    organization_id=str(asset.organization_id),
                    asset_id=str(asset.id),
                    asset_type=asset.asset_type.value,
                    name=asset.name,
                )
                for rel in asset.relationships:
                    await projector.project_asset_relationship(
                        organization_id=str(asset.organization_id),
                        source_asset_id=str(asset.id),
                        target_asset_id=rel.target_asset_id,
                        relationship_type=rel.relationship_type.value,
                    )
                await graph_uow.commit()
        except Exception:
            logger.warning(
                "security_graph: asset projection failed for asset_id=%s", asset.id, exc_info=True,
            )


def _map_target_type_to_asset_type(target_type: str) -> AssetType:
    mapping = {
        "llm_application": AssetType.AI_APPLICATION,
        "ai_agent": AssetType.AI_AGENT,
        "rag_system": AssetType.RAG_SYSTEM,
        "mcp_server": AssetType.MCP_SERVER,
        "ai_api": AssetType.AI_ENDPOINT,
        "ai_workflow": AssetType.AI_APPLICATION,
        "autonomous_agent": AssetType.AI_AGENT,
    }
    return mapping.get(target_type, AssetType.AI_APPLICATION)
