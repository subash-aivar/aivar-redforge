"""ORM models for the Behavioral Security bounded context — M20.

Four tables:
  behavior_entity_baselines   — rolling per-entity baseline stats
  behavior_observations       — per-window aggregated metrics per entity
  behavior_detections         — active detection lifecycle records
  behavior_detection_events   — detection timeline entries
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class BehaviorEntityBaselineModel(Base):
    """Rolling adaptive baseline for one source entity (IP address).

    Refreshed each detection cycle.  Stores precomputed p75 statistics
    and the serialized seen-destination sets for first-seen detection.
    """

    __tablename__ = "behavior_entity_baselines"
    __table_args__ = (
        UniqueConstraint("organization_id", "entity_type", "entity_id",
                         name="ux_beb_org_entity"),
        Index("ix_beb_org", "organization_id"),
        Index("ix_beb_org_updated", "organization_id", "updated_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(40), nullable=False)  # "IP_ADDRESS"
    entity_id: Mapped[str] = mapped_column(String(200), nullable=False)   # the IP
    baseline_confidence: Mapped[str] = mapped_column(String(30), nullable=False)
    window_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    p75_unique_dst_ips: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    p75_bytes_out: Mapped[float | None] = mapped_column(Float, nullable=True)
    p75_event_count: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # JSON-serialized set of seen dst_ips (list of strings)
    seen_dst_ips: Mapped[list[str] | None] = mapped_column(JSON, nullable=True, default=list)
    # JSON-serialized list of [src_ip, dst_ip, port] tuples
    seen_service_pairs: Mapped[list[Any] | None] = mapped_column(JSON, nullable=True, default=list)
    # JSON-serialized list of [src_ip, dst_ip] internal pairs
    seen_east_west_pairs: Mapped[list[Any] | None] = mapped_column(
        JSON, nullable=True, default=list
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BehaviorObservationModel(Base):
    """One time-window aggregation for one source entity.

    Idempotent: (organization_id, entity_id, window_start_ts) is unique.
    Used to build baselines and run per-window detections.
    """

    __tablename__ = "behavior_observations"
    __table_args__ = (
        UniqueConstraint("organization_id", "entity_id", "window_start_ts",
                         name="ux_bo_org_entity_window"),
        Index("ix_bo_org_entity", "organization_id", "entity_id"),
        Index("ix_bo_org_ts", "organization_id", "window_start_ts"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(200), nullable=False)  # src_ip
    entity_type: Mapped[str] = mapped_column(String(40), nullable=False)
    window_start_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unique_dst_ips: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unique_dst_ports: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_bytes_out: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    total_bytes_in: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    # JSON: list of dst_ips seen this window
    dst_ips_seen: Mapped[list[str] | None] = mapped_column(JSON, nullable=True, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BehaviorDetectionModel(Base):
    """A behavioral anomaly detection with full lifecycle tracking.

    correlation_key enforces exactly-one-active-detection per
    (organization_id, entity_id, detection_type) via partial unique index.
    """

    __tablename__ = "behavior_detections"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_bd_id_org"),
        Index("ix_bd_org_status", "organization_id", "status"),
        Index("ix_bd_org_entity", "organization_id", "entity_id"),
        Index("ix_bd_org_ts", "organization_id", "detected_at"),
        # Partial unique index: one active detection per correlation_key
        Index(
            "ux_bd_org_corr_active",
            "organization_id", "correlation_key",
            unique=True,
            postgresql_where=text("status NOT IN ('RESOLVED', 'CLOSED')"),
        ),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    # Unique key for deduplication: org+entity+type
    correlation_key: Mapped[str] = mapped_column(String(400), nullable=False)
    entity_type: Mapped[str] = mapped_column(String(40), nullable=False)
    entity_id: Mapped[str] = mapped_column(String(200), nullable=False)
    detection_type: Mapped[str] = mapped_column(String(60), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="DETECTED")
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    # Evidence JSON: signals, explanation, missing_evidence, metrics
    evidence: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True, default=dict)
    # Optional: secondary entity (e.g. dst_ip for a pair detection)
    secondary_entity_id: Mapped[str | None] = mapped_column(String(200), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Quiet-window counter for MONITORING → RESOLVED transition
    quiet_windows: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    observation_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    assigned_to: Mapped[str | None] = mapped_column(String(26), nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class BehaviorDetectionEventModel(Base):
    """Timeline entry for a behavioral detection."""

    __tablename__ = "behavior_detection_events"
    __table_args__ = (
        Index("ix_bde_detection", "detection_id"),
        Index("ix_bde_org_ts", "organization_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    detection_id: Mapped[str] = mapped_column(String(26), nullable=False)
    event_type: Mapped[str] = mapped_column(String(60), nullable=False)
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    actor_user_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
