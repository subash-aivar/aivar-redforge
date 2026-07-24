"""SQLAlchemy models for the execution schema."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_JSONB_PORTABLE = JSON().with_variant(JSONB, "postgresql")


_SCHEMA = "execution"


class KillSwitchStateModel(Base):
    __tablename__ = "kill_switch_states"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    scope: Mapped[str] = mapped_column(String(32), nullable=False)
    scope_ref: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    armed_state: Mapped[str] = mapped_column(String(32), nullable=False)
    trigger_authority_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    trigger_authority_role: Mapped[str | None] = mapped_column(String(128), nullable=True)
    trigger_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    trigger_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    trigger_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    release_authority_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    release_authority_role: Mapped[str | None] = mapped_column(String(128), nullable=True)
    release_countersign_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    release_countersign_role: Mapped[str | None] = mapped_column(String(128), nullable=True)
    release_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "scope", "scope_ref", name="uq_kill_switch_tenant_scope_ref"
        ),
        Index("ix_kill_switch_tenant_scope", "tenant_id", "scope"),
        {"schema": _SCHEMA},
    )


class ExecutionJournalModel(Base):
    __tablename__ = "execution_journals"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "engagement_id", name="uq_execution_journals_tenant_engagement"
        ),
        Index("ix_execution_journals_tenant_engagement", "tenant_id", "engagement_id"),
        {"schema": _SCHEMA},
    )


class JournalEntryModel(Base):
    __tablename__ = "journal_entries"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    journal_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.execution_journals.id", ondelete="CASCADE"),
        nullable=False,
    )
    entry_type: Mapped[str] = mapped_column(String(64), nullable=False)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_entry_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    attribution_operator_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), nullable=True
    )
    system_attribution: Mapped[str | None] = mapped_column(String(128), nullable=True)
    corrects_ref: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint(
            "journal_id", "sequence_number", name="uq_journal_entries_journal_seq"
        ),
        Index("ix_journal_entries_journal_seq", "journal_id", "sequence_number"),
        {"schema": _SCHEMA},
    )


class AttackActionModel(Base):
    """
    Partition-ready AttackAction table.

    Physical monthly RANGE partitions on execution_timestamp are created in
    migration 0067. Composite PK (id, execution_timestamp) required by PG.
    """

    __tablename__ = "attack_actions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    execution_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), primary_key=True, nullable=False
    )
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    engagement_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    operation_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    step_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    target_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    technique_id: Mapped[str] = mapped_column(String(256), nullable=False)
    technique_category: Mapped[str] = mapped_column(String(128), nullable=False)
    impact_ceiling: Mapped[str] = mapped_column(String(32), nullable=False)
    operator_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    worker_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    action_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    input_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    action_input_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    safety_check_json: Mapped[dict[str, Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    completion_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    output_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    output_storage_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    failure_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("ix_attack_actions_tenant_execution", "tenant_id", "execution_timestamp"),
        Index("ix_attack_actions_tenant_operation", "tenant_id", "operation_id"),
        Index("ix_attack_actions_tenant_engagement", "tenant_id", "engagement_id"),
        Index("ix_attack_actions_tenant_step", "tenant_id", "step_id"),
        Index("ix_attack_actions_tenant_state", "tenant_id", "state"),
        {"schema": _SCHEMA},
    )


class ExecutionWorkerModel(Base):
    __tablename__ = "execution_workers"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    worker_type: Mapped[str] = mapped_column(String(64), nullable=False)
    trust_level: Mapped[str] = mapped_column(String(32), nullable=False)
    health_status: Mapped[str] = mapped_column(String(32), nullable=False)
    network_zone: Mapped[str] = mapped_column(String(128), nullable=False)
    capabilities_json: Mapped[list[Any]] = mapped_column(_JSONB_PORTABLE, nullable=False)
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signer_operator_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    decommissioned_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (
        Index("ix_execution_workers_tenant_health", "tenant_id", "health_status"),
        Index("ix_execution_workers_tenant_zone", "tenant_id", "network_zone"),
        {"schema": _SCHEMA},
    )
