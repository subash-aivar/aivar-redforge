"""PostgreSQL repositories for integration_hub.

Session-per-call from an injected async_sessionmaker, matching the pattern
used across incident/posture_forecasting/threat_hunt/exposure_reporting.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from sqlalchemy import delete, select, update

from integration_hub.domain.aggregates.connector_health_record import ConnectorHealthRecord
from integration_hub.domain.aggregates.connector_registration import ConnectorRegistration
from integration_hub.domain.aggregates.discovered_asset import DiscoveredAsset
from integration_hub.domain.aggregates.sync_run import SyncRun
from integration_hub.domain.exceptions.domain_exceptions import ConcurrencyConflictError
from integration_hub.domain.repositories.i_connector_repositories import (
    IConnectorHealthRecordRepository,
    IConnectorRegistrationRepository,
)
from integration_hub.domain.repositories.i_discovery_repositories import (
    IDiscoveredAssetRepository,
    ISyncRunRepository,
)
from integration_hub.domain.value_objects.credentials import CredentialRef
from integration_hub.domain.value_objects.discovery import (
    AssetCategory,
    AssetIdentity,
    AssetRelationship,
    AssetSnapshot,
    ComplianceState,
    RelationshipType,
    RiskScore,
    SecurityState,
    SyncMode,
    SyncRunStatus,
    VendorType,
)
from integration_hub.domain.value_objects.enums import (
    CircuitState,
    ConnectorHealthStatus,
    ConnectorStatus,
    ConnectorType,
)
from integration_hub.domain.value_objects.identifiers import (
    ConnectorHealthRecordId,
    ConnectorId,
    EntityId,
)
from integration_hub.infrastructure.persistence.models import (
    AssetRelationshipModel,
    ConnectorHealthRecordModel,
    ConnectorRegistrationModel,
    DiscoveredAssetModel,
    SyncRunModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


def _registration_to_row(reg: ConnectorRegistration) -> ConnectorRegistrationModel:
    return ConnectorRegistrationModel(
        id=reg.connector_id.value,
        tenant_id=reg.tenant_id.value,
        connector_type=str(reg.connector_type),
        display_name=reg.display_name,
        status=reg.status.value,
        credential_vault_key=reg.credential_ref.vault_key,
        credential_type=reg.credential_ref.credential_type,
        base_url=reg.base_url,
        configuration=dict(reg.configuration) if reg.configuration else None,
        circuit_state=reg.circuit_state.value,
        circuit_failure_count=reg.circuit_failure_count,
        circuit_opened_at=reg.circuit_opened_at,
        created_at=reg.created_at,
        updated_at=reg.updated_at,
        last_health_check_at=reg.last_health_check_at,
    )


def _row_to_registration(row: ConnectorRegistrationModel) -> ConnectorRegistration:
    return ConnectorRegistration(
        connector_id=ConnectorId(row.id),
        tenant_id=EntityId.from_uuid(row.tenant_id),
        connector_type=row.connector_type,
        display_name=row.display_name,
        status=ConnectorStatus(row.status),
        credential_ref=CredentialRef(
            vault_key=row.credential_vault_key,
            tenant_id=str(row.tenant_id),
            credential_type=row.credential_type,
        ),
        base_url=row.base_url,
        configuration=dict(row.configuration) if row.configuration else None,
        created_at=row.created_at,
        last_health_check_at=row.last_health_check_at,
        circuit_state=CircuitState(row.circuit_state),
        circuit_failure_count=row.circuit_failure_count,
        circuit_opened_at=row.circuit_opened_at,
        updated_at=row.updated_at,
    )


class PgConnectorRegistrationRepository(IConnectorRegistrationRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save(self, registration: ConnectorRegistration, tenant_id: EntityId) -> None:
        async with self._session_factory() as session:
            await session.merge(_registration_to_row(registration))
            await session.commit()

    async def get(
        self, connector_id: ConnectorId, tenant_id: EntityId
    ) -> ConnectorRegistration | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(ConnectorRegistrationModel).where(
                        ConnectorRegistrationModel.tenant_id == tenant_id.value,
                        ConnectorRegistrationModel.id == connector_id.value,
                    )
                )
            ).scalar_one_or_none()
            return _row_to_registration(row) if row is not None else None

    async def find_healthy_for_action_type(
        self, tenant_id: EntityId, connector_type: ConnectorType
    ) -> list[ConnectorRegistration]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(ConnectorRegistrationModel).where(
                        ConnectorRegistrationModel.tenant_id == tenant_id.value,
                        ConnectorRegistrationModel.connector_type == str(connector_type),
                        ConnectorRegistrationModel.status.in_(
                            [ConnectorStatus.HEALTHY.value, ConnectorStatus.REGISTERED.value]
                        ),
                    )
                )
            ).scalars().all()
            return [_row_to_registration(r) for r in rows]

    async def find_all_for_tenant(self, tenant_id: EntityId) -> list[ConnectorRegistration]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(ConnectorRegistrationModel).where(
                        ConnectorRegistrationModel.tenant_id == tenant_id.value
                    )
                )
            ).scalars().all()
            return [_row_to_registration(r) for r in rows]


class PgConnectorHealthRecordRepository(IConnectorHealthRecordRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def append(self, record: ConnectorHealthRecord, tenant_id: EntityId) -> None:
        async with self._session_factory() as session:
            session.add(
                ConnectorHealthRecordModel(
                    id=record.record_id.value,
                    tenant_id=tenant_id.value,
                    connector_id=record.connector_id.value,
                    status=record.status.value,
                    response_time_ms=record.response_time_ms,
                    error_detail=record.error_detail,
                    checked_at=record.checked_at,
                )
            )
            await session.commit()

    async def find_latest_for_connector(
        self, connector_id: ConnectorId, tenant_id: EntityId, limit: int
    ) -> list[ConnectorHealthRecord]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(ConnectorHealthRecordModel)
                    .where(
                        ConnectorHealthRecordModel.tenant_id == tenant_id.value,
                        ConnectorHealthRecordModel.connector_id == connector_id.value,
                    )
                    .order_by(ConnectorHealthRecordModel.checked_at.desc())
                    .limit(limit)
                )
            ).scalars().all()
            return [
                ConnectorHealthRecord(
                    record_id=ConnectorHealthRecordId(r.id),
                    tenant_id=EntityId.from_uuid(r.tenant_id),
                    connector_id=ConnectorId(r.connector_id),
                    status=ConnectorHealthStatus(r.status),
                    response_time_ms=r.response_time_ms,
                    error_detail=r.error_detail,
                    checked_at=r.checked_at,
                )
                for r in rows
            ]


def _asset_to_row(asset: DiscoveredAsset) -> DiscoveredAssetModel:
    return DiscoveredAssetModel(
        id=asset.asset_id,
        tenant_id=asset.tenant_id.value,
        connector_id=asset.connector_id.value,
        vendor=asset.vendor.value,
        external_id=asset.identity.external_id,
        fingerprint=asset.identity.fingerprint,
        name=asset.name,
        category=asset.category.value,
        region=asset.region,
        owner=asset.owner,
        security_state=asset.security_state.value,
        compliance_state=asset.compliance_state.value,
        health_status=asset.health_status,
        risk_score=asset.risk_score.value,
        tags=dict(asset.tags) if asset.tags else None,
        metadata_=dict(asset.metadata) if asset.metadata else None,
        configuration=dict(asset.configuration) if asset.configuration else None,
        config_hash=asset.snapshot.config_hash,
        discovered_at=asset.discovered_at,
        last_synced_at=asset.last_synced_at,
    )


def _row_to_asset(
    row: DiscoveredAssetModel, relationships: list[AssetRelationshipModel]
) -> DiscoveredAsset:
    identity = AssetIdentity(
        vendor=VendorType(row.vendor),
        external_id=row.external_id,
        tenant_id=str(row.tenant_id),
    )
    asset = DiscoveredAsset(
        asset_id=row.id,
        tenant_id=EntityId.from_uuid(row.tenant_id),
        connector_id=ConnectorId(row.connector_id),
        identity=identity,
        name=row.name,
        category=AssetCategory(row.category),
        vendor=VendorType(row.vendor),
        region=row.region,
        owner=row.owner,
        security_state=SecurityState(row.security_state),
        compliance_state=ComplianceState(row.compliance_state),
        health_status=row.health_status,
        risk_score=RiskScore(row.risk_score),
        tags=dict(row.tags) if row.tags else None,
        metadata=dict(row.metadata_) if row.metadata_ else None,
        configuration=dict(row.configuration) if row.configuration else None,
        relationships=[
            AssetRelationship(
                relationship_type=RelationshipType(rel.relationship_type),
                target_external_id=rel.target_external_id,
                target_asset_id=str(rel.target_asset_id) if rel.target_asset_id else None,
                metadata=dict(rel.metadata_) if rel.metadata_ else {},
            )
            for rel in relationships
        ],
        snapshot=AssetSnapshot(
            config_hash=row.config_hash, region=row.region, owner=row.owner
        ),
        discovered_at=row.discovered_at,
        last_synced_at=row.last_synced_at,
        version=row.version,
    )
    return asset


class PgDiscoveredAssetRepository(IDiscoveredAssetRepository):
    """Postgres-backed asset repository. Relationships are stored in a
    separate join table (asset_relationships) rather than embedded JSON so
    they stay queryable/filterable; `save` replaces the full relationship
    set for the asset on each call (small per-asset cardinality expected).

    Uses an integer `version` column with an optimistic-lock UPDATE
    (WHERE version = <expected>) to guard against races between
    concurrent sync runs touching the same asset.
    """

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save(self, asset: DiscoveredAsset, tenant_id: EntityId) -> None:
        async with self._session_factory() as session:
            row_exists = (
                await session.execute(
                    select(DiscoveredAssetModel.id).where(
                        DiscoveredAssetModel.tenant_id == tenant_id.value,
                        DiscoveredAssetModel.id == asset.asset_id,
                    )
                )
            ).scalar_one_or_none()

            row = _asset_to_row(asset)
            if row_exists is None:
                row.version = 1
                session.add(row)
                asset.version = 1
            else:
                # Optimistic lock: the caller's in-memory `asset.version` is
                # whatever version it was loaded/created at. If a concurrent
                # writer already bumped the stored row past that version,
                # the WHERE clause matches zero rows and we raise instead
                # of silently overwriting the other writer's change.
                expected_version = asset.version
                values = {
                    k: v for k, v in row.__dict__.items() if not k.startswith("_")
                }
                values.pop("id", None)
                values.pop("tenant_id", None)
                values["version"] = expected_version + 1
                result = await session.execute(
                    update(DiscoveredAssetModel)
                    .where(
                        DiscoveredAssetModel.id == asset.asset_id,
                        DiscoveredAssetModel.tenant_id == tenant_id.value,
                        DiscoveredAssetModel.version == expected_version,
                    )
                    .values(**values)
                )
                if (result.rowcount or 0) == 0:  # type: ignore[attr-defined]
                    raise ConcurrencyConflictError(
                        f"DiscoveredAsset {asset.asset_id} was modified concurrently "
                        f"(expected version {expected_version})"
                    )
                asset.version = expected_version + 1

            await session.execute(
                delete(AssetRelationshipModel).where(
                    AssetRelationshipModel.source_asset_id == asset.asset_id,
                    AssetRelationshipModel.tenant_id == tenant_id.value,
                )
            )
            for rel in asset.relationships:
                session.add(
                    AssetRelationshipModel(
                        id=uuid4(),
                        tenant_id=tenant_id.value,
                        source_asset_id=asset.asset_id,
                        target_asset_id=(
                            UUID(rel.target_asset_id) if rel.target_asset_id else None
                        ),
                        target_external_id=rel.target_external_id,
                        relationship_type=rel.relationship_type.value,
                        metadata_=dict(rel.metadata) if rel.metadata else None,
                    )
                )
            await session.commit()

    async def _load_relationships(
        self, session: AsyncSession, asset_id: UUID, tenant_id: EntityId
    ) -> list[AssetRelationshipModel]:
        rows = (
            await session.execute(
                select(AssetRelationshipModel).where(
                    AssetRelationshipModel.source_asset_id == asset_id,
                    AssetRelationshipModel.tenant_id == tenant_id.value,
                )
            )
        ).scalars().all()
        return list(rows)

    async def get(self, asset_id: UUID, tenant_id: EntityId) -> DiscoveredAsset | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(DiscoveredAssetModel).where(
                        DiscoveredAssetModel.tenant_id == tenant_id.value,
                        DiscoveredAssetModel.id == asset_id,
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            relationships = await self._load_relationships(session, asset_id, tenant_id)
            return _row_to_asset(row, relationships)

    async def get_by_fingerprint(
        self, fingerprint: str, tenant_id: EntityId
    ) -> DiscoveredAsset | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(DiscoveredAssetModel).where(
                        DiscoveredAssetModel.tenant_id == tenant_id.value,
                        DiscoveredAssetModel.fingerprint == fingerprint,
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                return None
            relationships = await self._load_relationships(session, row.id, tenant_id)
            return _row_to_asset(row, relationships)

    async def get_by_fingerprints(
        self, fingerprints: list[str], tenant_id: EntityId
    ) -> dict[str, DiscoveredAsset]:
        if not fingerprints:
            return {}
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(DiscoveredAssetModel).where(
                        DiscoveredAssetModel.tenant_id == tenant_id.value,
                        DiscoveredAssetModel.fingerprint.in_(fingerprints),
                    )
                )
            ).scalars().all()
            by_source = await self._load_relationships_batch(
                session, [row.id for row in rows], tenant_id
            )
            return {
                row.fingerprint: _row_to_asset(row, by_source.get(row.id, []))
                for row in rows
            }

    async def save_many(self, assets: list[DiscoveredAsset], tenant_id: EntityId) -> None:
        """Persist a whole discovery page in one session/commit — the
        number of commits stays O(pages), not O(items). Per-asset
        create-vs-update + optimistic-lock logic is unchanged from
        `save()`, just not committed individually."""
        if not assets:
            return
        async with self._session_factory() as session:
            existing_ids = set(
                (
                    await session.execute(
                        select(DiscoveredAssetModel.id).where(
                            DiscoveredAssetModel.tenant_id == tenant_id.value,
                            DiscoveredAssetModel.id.in_([a.asset_id for a in assets]),
                        )
                    )
                ).scalars().all()
            )
            for asset in assets:
                row = _asset_to_row(asset)
                if asset.asset_id not in existing_ids:
                    row.version = 1
                    session.add(row)
                    asset.version = 1
                else:
                    expected_version = asset.version
                    values = {
                        k: v for k, v in row.__dict__.items() if not k.startswith("_")
                    }
                    values.pop("id", None)
                    values.pop("tenant_id", None)
                    values["version"] = expected_version + 1
                    result = await session.execute(
                        update(DiscoveredAssetModel)
                        .where(
                            DiscoveredAssetModel.id == asset.asset_id,
                            DiscoveredAssetModel.tenant_id == tenant_id.value,
                            DiscoveredAssetModel.version == expected_version,
                        )
                        .values(**values)
                    )
                    if (result.rowcount or 0) == 0:  # type: ignore[attr-defined]
                        raise ConcurrencyConflictError(
                            f"DiscoveredAsset {asset.asset_id} was modified concurrently "
                            f"(expected version {expected_version})"
                        )
                    asset.version = expected_version + 1

                await session.execute(
                    delete(AssetRelationshipModel).where(
                        AssetRelationshipModel.source_asset_id == asset.asset_id,
                        AssetRelationshipModel.tenant_id == tenant_id.value,
                    )
                )
                for rel in asset.relationships:
                    session.add(
                        AssetRelationshipModel(
                            id=uuid4(),
                            tenant_id=tenant_id.value,
                            source_asset_id=asset.asset_id,
                            target_asset_id=(
                                UUID(rel.target_asset_id) if rel.target_asset_id else None
                            ),
                            target_external_id=rel.target_external_id,
                            relationship_type=rel.relationship_type.value,
                            metadata_=dict(rel.metadata) if rel.metadata else None,
                        )
                    )
            await session.commit()

    async def _load_relationships_batch(
        self, session: AsyncSession, asset_ids: list[UUID], tenant_id: EntityId
    ) -> dict[UUID, list[AssetRelationshipModel]]:
        """Single `WHERE source_asset_id IN (...)` query for a whole page
        of assets, instead of one query per asset (N+1)."""
        if not asset_ids:
            return {}
        rows = (
            await session.execute(
                select(AssetRelationshipModel).where(
                    AssetRelationshipModel.source_asset_id.in_(asset_ids),
                    AssetRelationshipModel.tenant_id == tenant_id.value,
                )
            )
        ).scalars().all()
        by_source: dict[UUID, list[AssetRelationshipModel]] = {}
        for rel in rows:
            by_source.setdefault(rel.source_asset_id, []).append(rel)
        return by_source

    async def find_relationships_for_assets(
        self, asset_ids: list[UUID], tenant_id: EntityId
    ) -> dict[UUID, list[AssetRelationship]]:
        async with self._session_factory() as session:
            by_source = await self._load_relationships_batch(session, asset_ids, tenant_id)
            return {
                asset_id: [
                    AssetRelationship(
                        relationship_type=RelationshipType(rel.relationship_type),
                        target_external_id=rel.target_external_id,
                        target_asset_id=(
                            str(rel.target_asset_id) if rel.target_asset_id else None
                        ),
                        metadata=dict(rel.metadata_) if rel.metadata_ else {},
                    )
                    for rel in rels
                ]
                for asset_id, rels in by_source.items()
            }

    def _order_clause(self, order_by: str) -> Any:
        field = order_by.lstrip("-")
        column = getattr(DiscoveredAssetModel, field, DiscoveredAssetModel.discovered_at)
        return column.desc() if order_by.startswith("-") else column.asc()

    async def find_all_for_connector(
        self,
        connector_id: ConnectorId,
        tenant_id: EntityId,
        *,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[DiscoveredAsset]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(DiscoveredAssetModel)
                    .where(
                        DiscoveredAssetModel.tenant_id == tenant_id.value,
                        DiscoveredAssetModel.connector_id == connector_id.value,
                    )
                    .order_by(DiscoveredAssetModel.discovered_at.desc())
                    .limit(limit)
                    .offset(offset)
                )
            ).scalars().all()
            by_source = await self._load_relationships_batch(
                session, [row.id for row in rows], tenant_id
            )
            return [_row_to_asset(row, by_source.get(row.id, [])) for row in rows]

    async def find_all_for_tenant(
        self,
        tenant_id: EntityId,
        *,
        category: str | None = None,
        vendor: str | None = None,
        tag: str | None = None,
        limit: int = 100,
        offset: int = 0,
        order_by: str = "-discovered_at",
    ) -> list[DiscoveredAsset]:
        async with self._session_factory() as session:
            stmt = select(DiscoveredAssetModel).where(
                DiscoveredAssetModel.tenant_id == tenant_id.value
            )
            if category:
                stmt = stmt.where(DiscoveredAssetModel.category == category)
            if vendor:
                stmt = stmt.where(DiscoveredAssetModel.vendor == vendor)
            if tag:
                # Pushed into SQL via the JSONB `?` (has_key) operator —
                # tags is a flat dict[str, str], so "does this asset have
                # this tag key" is a key-existence check, not containment.
                # Supported by the GIN index added in migration 0155.
                stmt = stmt.where(DiscoveredAssetModel.tags.has_key(tag))
            stmt = stmt.order_by(self._order_clause(order_by)).limit(limit).offset(offset)
            rows = (await session.execute(stmt)).scalars().all()
            by_source = await self._load_relationships_batch(
                session, [row.id for row in rows], tenant_id
            )
            return [_row_to_asset(row, by_source.get(row.id, [])) for row in rows]

    async def delete(self, asset_id: UUID, tenant_id: EntityId) -> None:
        async with self._session_factory() as session:
            await session.execute(
                delete(DiscoveredAssetModel).where(
                    DiscoveredAssetModel.id == asset_id,
                    DiscoveredAssetModel.tenant_id == tenant_id.value,
                )
            )
            await session.commit()


class PgSyncRunRepository(ISyncRunRepository):
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def save(self, run: SyncRun, tenant_id: EntityId) -> None:
        async with self._session_factory() as session:
            await session.merge(
                SyncRunModel(
                    id=run.sync_run_id,
                    tenant_id=tenant_id.value,
                    connector_id=run.connector_id.value,
                    mode=run.mode.value,
                    status=run.status.value,
                    started_at=run.started_at,
                    completed_at=run.completed_at,
                    items_discovered=run.items_discovered,
                    items_created=run.items_created,
                    items_updated=run.items_updated,
                    items_deleted=run.items_deleted,
                    error=run.error,
                    cancelled=run.cancelled,
                    cursor=run.cursor,
                    pages_processed=run.pages_processed,
                )
            )
            await session.commit()

    @staticmethod
    def _row_to_sync_run(r: SyncRunModel) -> SyncRun:
        return SyncRun(
            sync_run_id=r.id,
            tenant_id=EntityId.from_uuid(r.tenant_id),
            connector_id=ConnectorId(r.connector_id),
            mode=SyncMode(r.mode),
            status=SyncRunStatus(r.status),
            started_at=r.started_at,
            completed_at=r.completed_at,
            items_discovered=r.items_discovered,
            items_created=r.items_created,
            items_updated=r.items_updated,
            items_deleted=r.items_deleted,
            error=r.error,
            cancelled=r.cancelled,
            cursor=r.cursor,
            pages_processed=r.pages_processed,
        )

    async def get(self, sync_run_id: UUID, tenant_id: EntityId) -> SyncRun | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(SyncRunModel).where(
                        SyncRunModel.tenant_id == tenant_id.value,
                        SyncRunModel.id == sync_run_id,
                    )
                )
            ).scalar_one_or_none()
            return self._row_to_sync_run(row) if row is not None else None

    async def find_running_for_connector(
        self, connector_id: ConnectorId, tenant_id: EntityId
    ) -> SyncRun | None:
        async with self._session_factory() as session:
            row = (
                await session.execute(
                    select(SyncRunModel).where(
                        SyncRunModel.tenant_id == tenant_id.value,
                        SyncRunModel.connector_id == connector_id.value,
                        SyncRunModel.status == SyncRunStatus.RUNNING.value,
                    )
                )
            ).scalars().first()
            return self._row_to_sync_run(row) if row is not None else None

    async def find_for_connector(
        self, connector_id: ConnectorId, tenant_id: EntityId, limit: int = 20
    ) -> list[SyncRun]:
        async with self._session_factory() as session:
            rows = (
                await session.execute(
                    select(SyncRunModel)
                    .where(
                        SyncRunModel.tenant_id == tenant_id.value,
                        SyncRunModel.connector_id == connector_id.value,
                    )
                    .order_by(SyncRunModel.started_at.desc())
                    .limit(limit)
                )
            ).scalars().all()
            return [self._row_to_sync_run(r) for r in rows]
