"""ORM models for the taskgraph schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from redforge.infrastructure.database.base import Base

_SCHEMA = "taskgraph"


class TaskGraphModel(Base):
    __tablename__ = "task_graphs"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(String(2048), nullable=False, default="")
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    version_major: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    version_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    version_patch: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    engagement_window_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    signed_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    signed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    signature: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    tasks: Mapped[list[CampaignTaskModel]] = relationship(
        "CampaignTaskModel",
        back_populates="graph",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    dependencies: Mapped[list[TaskDependencyModel]] = relationship(
        "TaskDependencyModel",
        back_populates="graph",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_task_graphs_tenant_id", "tenant_id"),
        Index("ix_task_graphs_tenant_state", "tenant_id", "state"),
        UniqueConstraint(
            "tenant_id",
            "id",
            "state",
            name="uq_task_graph_tenant_active",
        ),
        {"schema": _SCHEMA},
    )


class CampaignTaskModel(Base):
    __tablename__ = "campaign_tasks"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    graph_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.task_graphs.id", ondelete="CASCADE"),
        nullable=False,
    )
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    task_type: Mapped[str] = mapped_column(String(32), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    criticality: Mapped[str] = mapped_column(String(32), nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    operation_template_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True
    )
    human_approval_config_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True
    )
    barrier_policy_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True
    )
    rollback_config_json: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB, nullable=True
    )
    task_group_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    rollback_task_ref_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), nullable=True
    )

    graph: Mapped[TaskGraphModel] = relationship(
        "TaskGraphModel", back_populates="tasks"
    )

    __table_args__ = (
        Index("ix_campaign_tasks_graph_id", "graph_id"),
        Index("ix_campaign_tasks_tenant_id", "tenant_id"),
        {"schema": _SCHEMA},
    )


class TaskDependencyModel(Base):
    __tablename__ = "task_dependencies"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    graph_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.task_graphs.id", ondelete="CASCADE"),
        nullable=False,
    )
    predecessor_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    successor_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    predicate: Mapped[str] = mapped_column(String(64), nullable=False)
    objective_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)

    graph: Mapped[TaskGraphModel] = relationship(
        "TaskGraphModel", back_populates="dependencies"
    )

    __table_args__ = (
        Index("ix_task_dependencies_graph_id", "graph_id"),
        Index("ix_task_dependencies_predecessor", "graph_id", "predecessor_id"),
        Index("ix_task_dependencies_successor", "graph_id", "successor_id"),
        {"schema": _SCHEMA},
    )
