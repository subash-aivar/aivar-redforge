"""SQLAlchemy models for ai_supply_chain schema (migration 0078)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    DateTime,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class SupplyChainBase(DeclarativeBase):
    pass


class ModelProvenanceModel(SupplyChainBase):
    __tablename__ = "model_provenance"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "ai_system_asset_id", name="uq_model_provenance_tenant_asset"
        ),
        {"schema": "ai_supply_chain"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    ai_system_asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    model_origin: Mapped[str] = mapped_column(String(64), nullable=False)
    integrity_status: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    operational_status: Mapped[str] = mapped_column(String(64), nullable=False)
    artifact_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    current_checksum_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    last_verified_checksum_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    signature_chain_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    source_registry_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    training_lineage_json: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    last_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class ProvenanceChainEntryModel(SupplyChainBase):
    """Append-only audit trail — legally_significant_audit_trail: true."""

    __tablename__ = "provenance_chain_entries"
    __table_args__ = ({"schema": "ai_supply_chain"},)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    provenance_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    entry_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    verification_method: Mapped[str | None] = mapped_column(String(64), nullable=True)
    trust_delegation_note: Mapped[str] = mapped_column(Text, nullable=False, default="")
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")


class ModelBillOfMaterialsModel(SupplyChainBase):
    __tablename__ = "model_bill_of_materials"
    __table_args__ = (
        UniqueConstraint("tenant_id", "provenance_id", name="uq_mbom_tenant_provenance"),
        {"schema": "ai_supply_chain"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    provenance_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    completed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class MBOMComponentModel(SupplyChainBase):
    """Append-only MBOM components."""

    __tablename__ = "mbom_components"
    __table_args__ = ({"schema": "ai_supply_chain"},)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    mbom_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    component_type: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    version: Mapped[str] = mapped_column(String(128), nullable=False)
    source: Mapped[str] = mapped_column(String(256), nullable=False)
    checksum: Mapped[str] = mapped_column(String(128), nullable=False)
    known_cve_ids_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)


class AIDiscoveryScanRunModel(SupplyChainBase):
    __tablename__ = "ai_discovery_scan_runs"
    __table_args__ = ({"schema": "ai_supply_chain"},)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(64), nullable=False)
    sources_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    discovered_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unmatched_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_partitions_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    api_calls_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    partial: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)


class TenantVerificationSettingsModel(SupplyChainBase):
    __tablename__ = "tenant_verification_settings"
    __table_args__ = ({"schema": "ai_supply_chain"},)

    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    size_threshold_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    monthly_egress_budget_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    egress_bytes_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_api_calls_per_scan: Mapped[int] = mapped_column(Integer, nullable=False, default=1000)
    max_concurrent_accounts: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
