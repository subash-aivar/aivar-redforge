"""ORM models mapping the `integration_hub` schema (migrations 0125-0126,
0140 for asset discovery)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")


_SCHEMA = "integration_hub"


class ConnectorRegistrationModel(Base):
    __tablename__ = "connector_registrations"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    connector_type: Mapped[str] = mapped_column(String(50), nullable=False)
    display_name: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    credential_vault_key: Mapped[str] = mapped_column(Text, nullable=False)
    credential_type: Mapped[str] = mapped_column(String(30), nullable=False)
    base_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    configuration: Mapped[dict[str, Any] | None] = mapped_column(_JSONB_PORTABLE, nullable=True)
    circuit_state: Mapped[str] = mapped_column(String(20), nullable=False)
    circuit_failure_count: Mapped[int] = mapped_column(Integer, nullable=False)
    circuit_opened_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_health_check_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ConnectorHealthRecordModel(Base):
    __tablename__ = "connector_health_records"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    connector_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    response_time_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DiscoveredAssetModel(Base):
    __tablename__ = "discovered_assets"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    connector_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    vendor: Mapped[str] = mapped_column(String(30), nullable=False)
    external_id: Mapped[str] = mapped_column(Text, nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(30), nullable=False)
    region: Mapped[str | None] = mapped_column(Text, nullable=True)
    owner: Mapped[str | None] = mapped_column(Text, nullable=True)
    security_state: Mapped[str] = mapped_column(String(20), nullable=False)
    compliance_state: Mapped[str] = mapped_column(String(20), nullable=False)
    health_status: Mapped[str | None] = mapped_column(String(30), nullable=True)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False)
    tags: Mapped[dict[str, Any] | None] = mapped_column(_JSONB_PORTABLE, nullable=True)
    metadata_: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata", _JSONB_PORTABLE, nullable=True
    )
    configuration: Mapped[dict[str, Any] | None] = mapped_column(_JSONB_PORTABLE, nullable=True)
    config_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_synced_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, server_default="1")


class AssetRelationshipModel(Base):
    __tablename__ = "asset_relationships"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    source_asset_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.discovered_assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_asset_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    target_external_id: Mapped[str] = mapped_column(Text, nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(30), nullable=False)
    metadata_: Mapped[dict[str, Any] | None] = mapped_column(
        "metadata", _JSONB_PORTABLE, nullable=True
    )


class SyncRunModel(Base):
    __tablename__ = "sync_runs"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    connector_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    items_discovered: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    items_created: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    items_updated: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    items_deleted: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    cancelled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    cursor: Mapped[str | None] = mapped_column(Text, nullable=True)
    pages_processed: Mapped[int] = mapped_column(Integer, nullable=False, server_default="0")
