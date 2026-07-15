"""ORM models for the DDoS Detection & Defense Center — M19.

Six tables:
  ddos_protected_resources   — declared monitoring targets (per org)
  ddos_detection_policies    — per-resource detection configuration
  ddos_observation_windows   — persisted aggregation snapshots (baseline feed)
  ddos_incidents             — correlated attack lifecycle
  ddos_incident_events       — incident timeline entries
  ddos_mitigation_recommendations — human-approval-gated action proposals
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class DDoSProtectedResourceModel(Base):
    """A declared protected resource — the scope of DDoS monitoring."""

    __tablename__ = "ddos_protected_resources"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_dpr_id_org"),
        UniqueConstraint("organization_id", "name", name="ux_dpr_org_name"),
        Index("ix_dpr_org", "organization_id"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Monitoring scope: ip_range (CIDR), asset_id reference, or freeform label
    scope_type: Mapped[str] = mapped_column(String(20), nullable=False)  # "cidr"|"asset"|"any"
    scope_value: Mapped[str | None] = mapped_column(String(200), nullable=True)
    # Critically affects severity scoring
    criticality: Mapped[str] = mapped_column(String(20), nullable=False, default="MEDIUM")
    # Destination ports to monitor (JSON list of ints, None = all)
    monitored_ports: Mapped[list[int] | None] = mapped_column(JSON, nullable=True)
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[str] = mapped_column(String(26), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DDoSDetectionPolicyModel(Base):
    """Detection configuration per protected resource."""

    __tablename__ = "ddos_detection_policies"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_ddp_id_org"),
        UniqueConstraint("organization_id", "resource_id", name="ux_ddp_org_resource"),
        ForeignKeyConstraint(
            ["resource_id", "organization_id"],
            ["ddos_protected_resources.id", "ddos_protected_resources.organization_id"],
            name="fk_ddp_same_tenant_resource",
            ondelete="CASCADE",
        ),
        Index("ix_ddp_org", "organization_id"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(26), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    # Profile: BASELINE | BALANCED | HIGH_SENSITIVITY | CUSTOM
    profile: Mapped[str] = mapped_column(String(20), nullable=False, default="BALANCED")
    # Static thresholds (used when adaptive baseline is COLD_START)
    static_bps_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    static_pps_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    static_fps_threshold: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Detection window duration in seconds
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)
    # Minimum windows in breach before escalating from DETECTED → ACTIVE
    min_breach_windows: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Quiet period windows to reach RESOLVED
    quiet_period_windows: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    # Mitigation mode: RECOMMEND_ONLY | APPROVAL_REQUIRED | NOT_CONFIGURED
    mitigation_mode: Mapped[str] = mapped_column(
        String(20), nullable=False, default="RECOMMEND_ONLY"
    )
    # Suppression windows (JSON list of {"start": "HH:MM", "end": "HH:MM", "days": [0..6]})
    suppression_windows: Mapped[list[Any] | None] = mapped_column(JSON, nullable=True)
    created_by: Mapped[str] = mapped_column(String(26), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DDoSObservationWindowModel(Base):
    """Persisted aggregation snapshot for one time window.

    The primary input to the baseline engine and the canonical source
    for traffic-over-time charts. One row per (org, resource, window_start).
    """

    __tablename__ = "ddos_observation_windows"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_dow_id_org"),
        UniqueConstraint(
            "organization_id", "resource_id", "window_start_ts",
            name="ux_dow_org_resource_window",
        ),
        Index("ix_dow_org_resource_ts", "organization_id", "resource_id", "window_start_ts"),
        Index("ix_dow_org_ts", "organization_id", "window_start_ts"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(26), nullable=False)
    window_start_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_end_ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_bytes_in: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    total_bytes_out: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    total_packets_in: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    total_packets_out: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    unique_src_ips: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    unique_dst_ports: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # JSON: {"tcp": N, "udp": M, ...}
    protocol_counts: Mapped[dict[str, int]] = mapped_column(JSON, nullable=False, default=dict)
    alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    syn_pattern_alert_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Detection outcome for this window
    detection_fired: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    severity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    classification: Mapped[str | None] = mapped_column(String(60), nullable=True)
    matched_signals: Mapped[list[Any]] = mapped_column(JSON, nullable=False, default=list)
    incident_id: Mapped[str | None] = mapped_column(String(26), nullable=True)
    computed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class DDoSIncidentModel(Base):
    """DDoS incident — correlated group of detection windows."""

    __tablename__ = "ddos_incidents"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_di_id_org"),
        Index("ix_di_org_status", "organization_id", "status"),
        Index("ix_di_org_resource", "organization_id", "resource_id"),
        Index("ix_di_org_detected", "organization_id", "first_detected_at"),
        # Partial unique index: at most one active/open incident per resource per org.
        # Covers DETECTED, ACTIVE, ESCALATED, MITIGATING, MONITORING — not RESOLVED/CLOSED.
        # Migration 0032. Enforces the invariant the SAVEPOINT+refetch pattern depends on.
        Index(
            "uix_di_one_active_per_resource",
            "organization_id",
            "resource_id",
            unique=True,
            postgresql_where=text(
                "status IN ('DETECTED', 'ACTIVE', 'ESCALATED', 'MITIGATING', 'MONITORING')"
            ),
        ),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(26), nullable=False)
    resource_name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="DETECTED")
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="LOW")
    classification: Mapped[str] = mapped_column(
        String(60), nullable=False, default="UNCLASSIFIED_DDOS_SUSPECTED"
    )
    first_detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    peak_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Peak metrics observed during the incident
    peak_bytes_per_second: Mapped[float | None] = mapped_column(Float, nullable=True)
    peak_packets_per_second: Mapped[float | None] = mapped_column(Float, nullable=True)
    peak_flows_per_second: Mapped[float | None] = mapped_column(Float, nullable=True)
    peak_unique_src_ips: Mapped[int | None] = mapped_column(Integer, nullable=True)
    peak_deviation_multiplier: Mapped[float | None] = mapped_column(Float, nullable=True)
    # Evidence snapshot from the window that opened this incident
    opening_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    # Latest evidence snapshot
    latest_evidence: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    # Quiet window count (for RESOLVED transition)
    consecutive_quiet_windows: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Concurrency safety: optimistic version for state transitions
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class DDoSIncidentEventModel(Base):
    """Timeline entry for a DDoS incident (immutable append-only log)."""

    __tablename__ = "ddos_incident_events"
    __table_args__ = (
        Index("ix_die_incident", "incident_id"),
        Index("ix_die_org_ts", "organization_id", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(26), nullable=False)
    event_type: Mapped[str] = mapped_column(String(60), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # Human-readable description
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Structured payload for the SSE stream and investigation view
    payload: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    actor_id: Mapped[str | None] = mapped_column(String(26), nullable=True)


class DDoSMitigationRecommendationModel(Base):
    """Mitigation recommendation — requires explicit human approval.

    Default mitigation mode is RECOMMEND_ONLY: detection generates a
    recommendation row, no execution happens until an OWNER/ADMIN/
    SECURITY_MANAGER approves it (DDOS_MITIGATION_APPROVE permission).
    Approved recommendations can be executed through a configured
    provider adapter. Without a configured provider the execution
    status stays NOT_STARTED and the UI shows NOT CONFIGURED.
    """

    __tablename__ = "ddos_mitigation_recommendations"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_dmr_id_org"),
        Index("ix_dmr_incident", "incident_id"),
        Index("ix_dmr_org_status", "organization_id", "approval_status"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    incident_id: Mapped[str] = mapped_column(String(26), nullable=False)
    recommendation_type: Mapped[str] = mapped_column(String(40), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    # Structured recommendation detail (scoped to specific IPs/ports/rates)
    recommendation_detail: Mapped[dict[str, Any]] = mapped_column(
        JSON, nullable=False, default=dict
    )
    approval_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="PENDING"
    )
    approved_by: Mapped[str | None] = mapped_column(String(26), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejected_by: Mapped[str | None] = mapped_column(String(26), nullable=True)
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    execution_status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="NOT_STARTED"
    )
    executed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    # Provider that would execute (None = NOT CONFIGURED)
    provider_type: Mapped[str | None] = mapped_column(String(40), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
