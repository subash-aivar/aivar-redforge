"""SQLAlchemy models for ai_posture schema (migrations 0076-0077)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")



class AIPostureBase(DeclarativeBase):
    pass


class AISystemAssetModel(AIPostureBase):
    __tablename__ = "ai_system_assets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "asset_ref_id", name="uq_ai_system_assets_tenant_asset_ref"),
        {"schema": "ai_posture"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    asset_ref_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    asset_ref_type: Mapped[str] = mapped_column(String(64), nullable=False, default="AIAsset")
    lifecycle_state: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    registration_status: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    ai_system_kind: Mapped[str | None] = mapped_column(String(64), nullable=True)
    business_owner_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    business_owner_name: Mapped[str | None] = mapped_column(String(256), nullable=True)
    data_sensitivity: Mapped[str] = mapped_column(String(64), nullable=False)
    discovery_source: Mapped[str] = mapped_column(String(64), nullable=False)
    discovery_first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    discovery_last_confirmed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    threat_profile_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    risk_score_snapshot_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class ShadowAIAlertModel(AIPostureBase):
    __tablename__ = "shadow_ai_alerts"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "discovery_source",
            "fingerprint_hash",
            name="uq_shadow_ai_alerts_tenant_source_fp",
        ),
        {"schema": "ai_posture"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    discovery_source: Mapped[str] = mapped_column(String(64), nullable=False)
    cloud_account: Mapped[str] = mapped_column(String(256), nullable=False)
    resource_identifier: Mapped[str] = mapped_column(String(512), nullable=False)
    service_type: Mapped[str] = mapped_column(String(256), nullable=False)
    region: Mapped[str] = mapped_column(String(128), nullable=False)
    fingerprint_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    triage_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    resolution_action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    linked_asset_id: Mapped[UUID | None] = mapped_column(PGUUID(as_uuid=True), nullable=True)
    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_confirmed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AIPostureTenantSettingsModel(AIPostureBase):
    __tablename__ = "ai_posture_tenant_settings"
    __table_args__ = ({"schema": "ai_posture"},)

    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    discovery_only_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AIThreatProfileModel(AIPostureBase):
    __tablename__ = "ai_threat_profiles"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "ai_system_asset_id", name="uq_ai_threat_profiles_tenant_asset"
        ),
        {"schema": "ai_posture"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    ai_system_asset_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True), nullable=False, index=True
    )
    ai_system_kind: Mapped[str] = mapped_column(String(64), nullable=False)
    prompt_injection_json: Mapped[dict[str, Any] | None] = mapped_column(
        _JSONB_PORTABLE, nullable=True,
    )
    model_extraction_json: Mapped[dict[str, Any] | None] = mapped_column(
        _JSONB_PORTABLE, nullable=True,
    )
    training_data_leakage_json: Mapped[dict[str, Any] | None] = mapped_column(
        _JSONB_PORTABLE, nullable=True,
    )
    category_assessments_json: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list
    )
    evidence_refs_json: Mapped[list[Any]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list,
    )
    last_assessed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    requires_reassessment: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    archived: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AIRiskScoreSnapshotModel(AIPostureBase):
    __tablename__ = "ai_risk_score_snapshots"
    __table_args__ = ({"schema": "ai_posture"},)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    ai_system_asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    composite_score: Mapped[float] = mapped_column(Float, nullable=False)
    score_components_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    staleness_bound_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    score_input_version: Mapped[str] = mapped_column(String(64), nullable=False)


class AIComplianceMappingModel(AIPostureBase):
    __tablename__ = "ai_compliance_mappings"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "ai_system_asset_id",
            "framework_id",
            "control_id",
            name="uq_compliance_mapping_asset_control",
        ),
        {"schema": "ai_posture"},
    )

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    ai_system_asset_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    framework_id: Mapped[str] = mapped_column(String(64), nullable=False)
    control_id: Mapped[str] = mapped_column(String(128), nullable=False)
    control_title: Mapped[str] = mapped_column(String(512), nullable=False)
    control_status: Mapped[str] = mapped_column(String(64), nullable=False)
    requires_human_attestation: Mapped[bool] = mapped_column(Boolean, nullable=False)
    evaluation_mode: Mapped[str] = mapped_column(String(64), nullable=False)
    attestor_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    attested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attestation_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class AIComplianceControlClassificationModel(AIPostureBase):
    __tablename__ = "ai_compliance_control_classifications"
    __table_args__ = ({"schema": "ai_posture"},)

    framework_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    control_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    control_title: Mapped[str] = mapped_column(String(512), nullable=False)
    requires_human_attestation: Mapped[bool] = mapped_column(Boolean, nullable=False)


class AIPostureReadModelRow(AIPostureBase):
    __tablename__ = "ai_posture_read_models"
    __table_args__ = ({"schema": "ai_posture"},)

    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    view_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    payload_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    last_event_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    projection_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AISecurityGraphNodeModel(AIPostureBase):
    __tablename__ = "ai_security_graph_nodes"
    __table_args__ = ({"schema": "ai_posture"},)

    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    node_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    node_key: Mapped[str] = mapped_column(String(256), primary_key=True)
    properties_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    last_event_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")


class AISecurityGraphEdgeModel(AIPostureBase):
    __tablename__ = "ai_security_graph_edges"
    __table_args__ = ({"schema": "ai_posture"},)

    tenant_id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True)
    edge_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    from_key: Mapped[str] = mapped_column(String(256), primary_key=True)
    to_key: Mapped[str] = mapped_column(String(256), primary_key=True)
    properties_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    last_event_id: Mapped[str] = mapped_column(String(128), nullable=False, default="")
