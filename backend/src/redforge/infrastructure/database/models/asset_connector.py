"""SQLAlchemy ORM models for the unified asset/connector foundation — M3.

Both tables follow the document-store pattern (JSON blob + a handful of
relational columns for tenant-scoped uniqueness/query), matching the
`providers` precedent from Sprint 42-43 — the rich nested value-object
graphs on `AIAsset`/`Connector` (fingerprints, version history,
relationships, discovery history) are not flattened into a normalized
relational schema, which would require dozens of join tables for
marginal query benefit at M3's scale.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class AIAssetModel(Base):
    __tablename__ = "ai_assets"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    discovery_source: Mapped[str] = mapped_column(String(50), nullable=False)
    lifecycle_stage: Mapped[str] = mapped_column(String(30), nullable=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ConnectorModel(Base):
    __tablename__ = "connectors"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    connector_type: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    data: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
