"""SQLAlchemy models for exposure schema (Phase 1)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")



class ExposureBase(DeclarativeBase):
    pass


class ExposureRecordModel(ExposureBase):
    __tablename__ = "exposure_records"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "asset_ref_id",
            "signal_domain",
            "signal_source_ref",
            name="uq_exposure_identity",
        ),
        {"schema": "exposure"},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    asset_ref_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    signal_domain: Mapped[str] = mapped_column(String(64), nullable=False)
    signal_source_ref: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    base_exposure_level: Mapped[float] = mapped_column(Float, nullable=False)
    current_exposure_score: Mapped[float] = mapped_column(Float, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    suppression_justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    amplifiers_json: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list,
    )
    technique_refs_json: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list,
    )
    cve_ids_json: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False, default=list)
    asset_classes_json: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list,
    )


class ThreatActorMatchCacheModel(ExposureBase):
    __tablename__ = "threat_actor_match_cache"
    __table_args__ = ({"schema": "exposure"},)

    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    entries_json: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict,
    )
    asset_class_entries_json: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    technique_entries_json: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict
    )
    ioc_entries_json: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict,
    )
    last_event_update_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_poll_update_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ExposureScoreSnapshotModel(ExposureBase):
    __tablename__ = "exposure_score_snapshots"
    __table_args__ = ({"schema": "exposure"},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    asset_ref_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    composite_score: Mapped[float] = mapped_column(Float, nullable=False)
    score_input_version: Mapped[int] = mapped_column(Integer, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    job_id: Mapped[str] = mapped_column(String(128), nullable=False)
    record_scores_json: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict,
    )


class AmplifierWeightConfigurationModel(ExposureBase):
    __tablename__ = "amplifier_weight_configurations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "version", name="uq_weight_version"),
        {"schema": "exposure"},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    weights_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    change_rationale: Mapped[str] = mapped_column(Text, nullable=False)
    changed_by: Mapped[str] = mapped_column(String(256), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PendingRecomputationModel(ExposureBase):
    __tablename__ = "pending_recomputations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "asset_ref_id", name="uq_pending_asset"),
        {"schema": "exposure"},
    )

    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    asset_ref_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    marked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    debounce_override_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bypass_debounce: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class ProcessedExposureSignalModel(ExposureBase):
    __tablename__ = "processed_exposure_signals"
    __table_args__ = ({"schema": "exposure"},)

    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TenantExposureProfileModel(ExposureBase):
    __tablename__ = "tenant_exposure_profiles"
    __table_args__ = ({"schema": "exposure"},)

    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    asset_scores_json: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict,
    )
    recomputing: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    recomputation_failed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=dict,
    )
