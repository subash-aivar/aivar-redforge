"""SQLAlchemy ORM models for Threat Fusion — M22 Phase 4 (migration 0037)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")



class FusedIndicatorModel(Base):
    __tablename__ = "fused_indicators"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    canonical_key: Mapped[str] = mapped_column(String(300), nullable=False, unique=True)
    indicator_type: Mapped[str] = mapped_column(String(30), nullable=False)
    display_name: Mapped[str] = mapped_column(String(512), nullable=False)
    lifecycle: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    risk_state: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str | None] = mapped_column(String(20), nullable=True)
    winner_source_system: Mapped[str | None] = mapped_column(String(30), nullable=True)
    risk_breakdown: Mapped[list[dict[str, Any]]] = mapped_column(
        _JSONB_PORTABLE, nullable=False, default=list
    )
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", _JSONB_PORTABLE, nullable=False, default=dict
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FusedIndicatorSourceModel(Base):
    __tablename__ = "fused_indicator_sources"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    indicator_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("fused_indicators.id", ondelete="CASCADE"), nullable=False
    )
    source_system: Mapped[str] = mapped_column(String(30), nullable=False)
    external_id: Mapped[str] = mapped_column(String(256), nullable=False)
    content_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    weight_applied: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    feed_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", _JSONB_PORTABLE, nullable=False, default=dict
    )


class FusedRelationshipModel(Base):
    __tablename__ = "fused_relationships"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    relationship_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_indicator_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("fused_indicators.id", ondelete="CASCADE"), nullable=False
    )
    target_indicator_id: Mapped[str] = mapped_column(
        String(26), ForeignKey("fused_indicators.id", ondelete="CASCADE"), nullable=False
    )
    source_canonical_key: Mapped[str] = mapped_column(String(300), nullable=False)
    target_canonical_key: Mapped[str] = mapped_column(String(300), nullable=False)
    stix_relationship_id: Mapped[str | None] = mapped_column(
        String(128), nullable=True, unique=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ThreatIntelFusionConfigModel(Base):
    __tablename__ = "threat_intel_fusion_config"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    source_system: Mapped[str] = mapped_column(String(30), nullable=False, unique=True)
    weight: Mapped[float] = mapped_column(Float, nullable=False)
    updated_by: Mapped[str] = mapped_column(String(26), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
