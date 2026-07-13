"""SQLAlchemy repository for the Connector aggregate — M3.

Serializes the full nested value-object graph, including
`discovery_history` (a tuple of `DiscoveryJobRecord` — this already
models exactly what M3 calls a "Discovery Run": a PENDING/RUNNING/
COMPLETED/FAILED/CANCELLED lifecycle record with observation counts).
No separate discovery_runs table exists — the Connector aggregate
already owns this history; splitting it into a second table would
create two sources of truth for the same data.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from redforge.domain.connectors.entity import Connector
from redforge.domain.connectors.value_objects import (
    ConnectorAuditEntry,
    ConnectorCapability,
    ConnectorCapabilityType,
    ConnectorConfiguration,
    ConnectorCredentialReference,
    ConnectorHealth,
    ConnectorHealthStatus,
    ConnectorStatus,
    ConnectorType,
    ConnectorVersion,
    CredentialType,
    DiscoveryJobRecord,
    DiscoveryJobStatus,
    SynchronizationPolicy,
    SyncJobRecord,
    SyncJobStatus,
)
from redforge.infrastructure.database.models.asset_connector import ConnectorModel
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


def _ensure_utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


def _connector_to_data(c: Connector) -> dict[str, Any]:
    return {
        "description": c.description,
        "version": {
            "connector_type_version": c.version.connector_type_version,
            "schema_version": c.version.schema_version,
            "min_platform_version": c.version.min_platform_version,
        },
        "capabilities": [
            {
                "capability_type": cap.capability_type.value,
                "asset_types_supported": list(cap.asset_types_supported),
                "description": cap.description,
            }
            for cap in c.capabilities
        ],
        "config": (
            {
                "base_url": c.config.base_url,
                "timeout_seconds": c.config.timeout_seconds,
                "max_retries": c.config.max_retries,
                "page_size": c.config.page_size,
                "verify_tls": c.config.verify_tls,
                "custom_config": [list(kv) for kv in c.config.custom_config],
            }
            if c.config
            else None
        ),
        "credential_ref": (
            {
                "reference_id": c.credential_ref.reference_id,
                "credential_type": c.credential_ref.credential_type.value,
                "description": c.credential_ref.description,
                "last_rotated_at_iso": c.credential_ref.last_rotated_at_iso,
            }
            if c.credential_ref
            else None
        ),
        "health": {
            "status": c.health.status.value,
            "last_check_at_iso": c.health.last_check_at_iso,
            "latency_ms": c.health.latency_ms,
            "error_message": c.health.error_message,
            "consecutive_failures": c.health.consecutive_failures,
        },
        "sync_policy": {
            "enabled": c.sync_policy.enabled,
            "cron_expression": c.sync_policy.cron_expression,
            "max_assets_per_run": c.sync_policy.max_assets_per_run,
            "full_sync_interval_hours": c.sync_policy.full_sync_interval_hours,
            "incremental": c.sync_policy.incremental,
            "backfill_on_enable": c.sync_policy.backfill_on_enable,
        },
        "discovery_history": [
            {
                "job_id": j.job_id,
                "status": j.status.value,
                "started_at_iso": j.started_at_iso,
                "completed_at_iso": j.completed_at_iso,
                "assets_discovered": j.assets_discovered,
                "assets_normalized": j.assets_normalized,
                "assets_failed": j.assets_failed,
                "error_message": j.error_message,
                "filters": [list(kv) for kv in j.filters],
            }
            for j in c.discovery_history
        ],
        "sync_history": [
            {
                "job_id": j.job_id,
                "status": j.status.value,
                "started_at_iso": j.started_at_iso,
                "completed_at_iso": j.completed_at_iso,
                "assets_added": j.assets_added,
                "assets_updated": j.assets_updated,
                "assets_unchanged": j.assets_unchanged,
                "assets_failed": j.assets_failed,
                "error_message": j.error_message,
                "is_full_sync": j.is_full_sync,
            }
            for j in c.sync_history
        ],
        "audit_trail": [
            {
                "event_type": a.event_type,
                "actor_id": a.actor_id,
                "occurred_at_iso": a.occurred_at_iso,
                "details": a.details,
            }
            for a in c.audit_trail
        ],
    }


def _model_to_connector(model: ConnectorModel) -> Connector:
    data = model.data
    version_data = data["version"]
    version = ConnectorVersion(
        connector_type_version=version_data["connector_type_version"],
        schema_version=version_data["schema_version"],
        min_platform_version=version_data.get("min_platform_version", "23.0.0"),
    )
    capabilities = tuple(
        ConnectorCapability(
            capability_type=ConnectorCapabilityType(cap["capability_type"]),
            asset_types_supported=tuple(cap.get("asset_types_supported", [])),
            description=cap.get("description", ""),
        )
        for cap in data.get("capabilities", [])
    )
    config_data = data.get("config")
    config = (
        ConnectorConfiguration(
            base_url=config_data["base_url"],
            timeout_seconds=config_data.get("timeout_seconds", 30),
            max_retries=config_data.get("max_retries", 3),
            page_size=config_data.get("page_size", 100),
            verify_tls=config_data.get("verify_tls", True),
            custom_config=tuple(tuple(kv) for kv in config_data.get("custom_config", [])),
        )
        if config_data
        else None
    )
    cred_data = data.get("credential_ref")
    credential_ref = (
        ConnectorCredentialReference(
            reference_id=cred_data["reference_id"],
            credential_type=CredentialType(cred_data["credential_type"]),
            description=cred_data.get("description", ""),
            last_rotated_at_iso=cred_data.get("last_rotated_at_iso", ""),
        )
        if cred_data
        else None
    )
    health_data = data["health"]
    health = ConnectorHealth(
        status=ConnectorHealthStatus(health_data["status"]),
        last_check_at_iso=health_data.get("last_check_at_iso", ""),
        latency_ms=health_data.get("latency_ms", 0.0),
        error_message=health_data.get("error_message", ""),
        consecutive_failures=health_data.get("consecutive_failures", 0),
    )
    sp_data = data["sync_policy"]
    sync_policy = SynchronizationPolicy(
        enabled=sp_data.get("enabled", False),
        cron_expression=sp_data.get("cron_expression", ""),
        max_assets_per_run=sp_data.get("max_assets_per_run", 10_000),
        full_sync_interval_hours=sp_data.get("full_sync_interval_hours", 24),
        incremental=sp_data.get("incremental", True),
        backfill_on_enable=sp_data.get("backfill_on_enable", True),
    )
    discovery_history = tuple(
        DiscoveryJobRecord(
            job_id=j["job_id"],
            status=DiscoveryJobStatus(j["status"]),
            started_at_iso=j["started_at_iso"],
            completed_at_iso=j.get("completed_at_iso", ""),
            assets_discovered=j.get("assets_discovered", 0),
            assets_normalized=j.get("assets_normalized", 0),
            assets_failed=j.get("assets_failed", 0),
            error_message=j.get("error_message", ""),
            filters=tuple(tuple(kv) for kv in j.get("filters", [])),
        )
        for j in data.get("discovery_history", [])
    )
    sync_history = tuple(
        SyncJobRecord(
            job_id=j["job_id"],
            status=SyncJobStatus(j["status"]),
            started_at_iso=j["started_at_iso"],
            completed_at_iso=j.get("completed_at_iso", ""),
            assets_added=j.get("assets_added", 0),
            assets_updated=j.get("assets_updated", 0),
            assets_unchanged=j.get("assets_unchanged", 0),
            assets_failed=j.get("assets_failed", 0),
            error_message=j.get("error_message", ""),
            is_full_sync=j.get("is_full_sync", False),
        )
        for j in data.get("sync_history", [])
    )
    audit_trail = tuple(
        ConnectorAuditEntry(
            event_type=a["event_type"],
            actor_id=a["actor_id"],
            occurred_at_iso=a["occurred_at_iso"],
            details=a.get("details", ""),
        )
        for a in data.get("audit_trail", [])
    )

    return Connector(
        id=EntityId.from_string(model.id),
        organization_id=EntityId.from_string(model.organization_id),
        connector_type=ConnectorType(model.connector_type),
        name=model.name,
        description=data.get("description", ""),
        version=version,
        capabilities=capabilities,
        status=ConnectorStatus(model.status),
        config=config,
        credential_ref=credential_ref,
        health=health,
        sync_policy=sync_policy,
        discovery_history=discovery_history,
        sync_history=sync_history,
        audit_trail=audit_trail,
        timestamps=AuditTimestamps(
            created_at=_ensure_utc(model.created_at),
            updated_at=_ensure_utc(model.updated_at),
        ),
    )


class SqlAlchemyConnectorRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, connector: Connector) -> None:
        model = ConnectorModel(
            id=str(connector.id),
            organization_id=str(connector.organization_id),
            connector_type=connector.connector_type.value,
            name=connector.name,
            status=connector.status.value,
            data=_connector_to_data(connector),
            created_at=connector.timestamps.created_at,
            updated_at=connector.timestamps.updated_at,
        )
        await self._session.merge(model)
        await self._session.flush()

    async def get_by_id_for_org(
        self, connector_id: str, organization_id: str
    ) -> Connector | None:
        result = await self._session.execute(
            select(ConnectorModel).where(
                ConnectorModel.id == connector_id,
                ConnectorModel.organization_id == organization_id,
            )
        )
        model = result.scalar_one_or_none()
        return _model_to_connector(model) if model else None

    async def list_for_org(self, organization_id: str) -> list[Connector]:
        result = await self._session.execute(
            select(ConnectorModel)
            .where(ConnectorModel.organization_id == organization_id)
            .order_by(ConnectorModel.created_at.desc())
        )
        return [_model_to_connector(m) for m in result.scalars().all()]
