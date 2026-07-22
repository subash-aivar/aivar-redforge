"""ORM models mapping the `lessons_learned` schema (migrations 0111-0112, 0152)."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_SCHEMA = "lessons_learned"


class LessonsLearnedRecordModel(Base):
    __tablename__ = "lessons_learned_records"
    __table_args__ = ({"schema": _SCHEMA},)

    ll_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    incident_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    reviewed_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finalized_by: Mapped[str | None] = mapped_column(String(256), nullable=True)
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    campaign_retargeting_suggestion_ref: Mapped[str | None] = mapped_column(
        String(256), nullable=True
    )
    confirmed_technique_ids: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class LessonItemModel(Base):
    __tablename__ = "lesson_items"
    __table_args__ = ({"schema": _SCHEMA},)

    item_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    ll_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    impact_summary: Mapped[str] = mapped_column(Text, nullable=False)


class ActionItemModel(Base):
    __tablename__ = "action_items"
    __table_args__ = ({"schema": _SCHEMA},)

    action_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    ll_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    owner: Mapped[str] = mapped_column(String(256), nullable=False)
    priority: Mapped[str] = mapped_column(String(64), nullable=False)
    due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class RecommendationModel(Base):
    __tablename__ = "recommendations"
    __table_args__ = ({"schema": _SCHEMA},)

    recommendation_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    ll_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    technique_ids: Mapped[list[Any]] = mapped_column(JSONB, nullable=False)


class PostIncidentReportModel(Base):
    __tablename__ = "post_incident_reports"
    __table_args__ = ({"schema": _SCHEMA},)

    report_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    incident_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    lessons_learned_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    format: Mapped[str] = mapped_column(String(32), nullable=False)
    artifact_ref: Mapped[str | None] = mapped_column(String(512), nullable=True)
    artifact_bytes: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exported_to: Mapped[str | None] = mapped_column(String(512), nullable=True)
