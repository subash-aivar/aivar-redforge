"""ORM models mapping the `playbook` schema (migrations 0114-0119, 0150)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_SCHEMA = "playbook"


class PlaybookModel(Base):
    __tablename__ = "playbooks"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    current_version_number: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_impact_level: Mapped[str] = mapped_column(String(20), nullable=False)
    created_by: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    approved_by_json: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)


class PlaybookVersionModel(Base):
    __tablename__ = "playbook_versions"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    playbook_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    published_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class PlaybookActionStepModel(Base):
    __tablename__ = "playbook_action_steps"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    version_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    step_number: Mapped[int] = mapped_column(Integer, nullable=False)
    action_type: Mapped[str] = mapped_column(Text, nullable=False)
    connector_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_selector_expr: Mapped[str] = mapped_column(Text, nullable=False)
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    impact_level: Mapped[str] = mapped_column(String(20), nullable=False)
    rollback_definition: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    max_execution_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=120)


class PlaybookTriggerConfigModel(Base):
    __tablename__ = "playbook_trigger_configs"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    playbook_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    source_context: Mapped[str] = mapped_column(String(40), nullable=False)
    trigger_type: Mapped[str] = mapped_column(Text, nullable=False)
    severity_threshold: Mapped[str | None] = mapped_column(String(40), nullable=True)
    asset_tag_filter: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    rate_limit_window_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    rate_limit_max_invocations: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class PlaybookTestResultModel(Base):
    __tablename__ = "playbook_test_results"
    __table_args__ = ({"schema": _SCHEMA},)

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    playbook_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    version_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    content_hash_at_test: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    steps_tested: Mapped[int] = mapped_column(Integer, nullable=False)
    steps_passed: Mapped[int] = mapped_column(Integer, nullable=False)
    coverage_paths: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    executed_by: Mapped[str] = mapped_column(Text, nullable=False)
    executed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)


class AutomationPolicyModel(Base):
    __tablename__ = "automation_policy"
    __table_args__ = ({"schema": _SCHEMA},)

    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    kill_switch_state: Mapped[str] = mapped_column(String(20), nullable=False, default="ARMED")
    kill_switch_triggered_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    kill_switch_triggered_by: Mapped[str | None] = mapped_column(Text, nullable=True)
    max_concurrent_executions: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    max_actions_per_hour: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    allowed_connector_types: Mapped[list[Any] | None] = mapped_column(JSONB, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
