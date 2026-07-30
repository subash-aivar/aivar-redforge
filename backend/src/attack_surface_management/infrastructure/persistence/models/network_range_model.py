"""ORM model for the `NetworkRange` aggregate (M49C).

A single table — `NetworkRange` has no owned child entities (see its
module docstring: assets are only counted, never attached by
reference), so unlike `Asset` there is nothing to eager-load and no
`lazy="selectin"` relationship is needed here."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Index, Integer, String
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class NetworkRangeModel(Base):
    __tablename__ = "attack_surface_network_ranges"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    discovery_source: Mapped[str] = mapped_column(String(32), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False)
    asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        Index("ix_attack_surface_network_ranges_tenant", "tenant_id"),
        Index(
            "ix_attack_surface_network_ranges_tenant_lifecycle",
            "tenant_id",
            "lifecycle_state",
        ),
    )
