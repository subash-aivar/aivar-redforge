"""SQLAlchemy ORM model for campaign_results table."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")



class CampaignResultModel(Base):
    """Persisted outcome of a completed red team campaign.

    Written once after campaign completion.  Scoped by organization_id
    for multi-tenant isolation.  Read-only after creation.
    """

    __tablename__ = "campaign_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(String(36), nullable=False)
    state: Mapped[str] = mapped_column(String(50), nullable=False)
    goal_achieved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    objective_name: Mapped[str] = mapped_column(String(200), nullable=False, default="")
    total_nodes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    nodes_executed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    completed_nodes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed_nodes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    blocked_nodes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    injected_nodes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    intelligence_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    graph_snapshot: Mapped[Any] = mapped_column(_JSONB_PORTABLE, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
