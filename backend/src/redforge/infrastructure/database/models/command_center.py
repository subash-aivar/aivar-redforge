"""SQLAlchemy ORM models for the Security Operations Command Center — M18.

See migration 0028's own docstring for the boundary rationale. Two
tables only: the provider-neutral integration BOUNDARY
(`integration_providers`) and explicit admin-authored network-zone
classification (`network_zone_assignments`). Neither stores telemetry
or secrets; the command center owns no authoritative domain truth.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class IntegrationProviderModel(Base):
    """A provider DESCRIPTOR for one external-telemetry integration type,
    per organization. Never stores secrets or telemetry — only a type,
    a display name, a status, an allowlisted non-secret config blob, and
    when telemetry was last received. Zero rows = every integration
    reports NOT_CONFIGURED."""

    __tablename__ = "integration_providers"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_intp_id_org"),
        UniqueConstraint("organization_id", "integration_type", name="ux_intp_org_type"),
        Index("ix_intp_org_type", "organization_id", "integration_type"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    integration_type: Mapped[str] = mapped_column(String(30), nullable=False)
    provider_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    config: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    last_telemetry_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    registered_by: Mapped[str] = mapped_column(String(26), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class NetworkZoneAssignmentModel(Base):
    """Explicit, admin-authored zone classification for one AIAsset.
    Composite FK to ai_assets(id, organization_id) makes cross-tenant
    assignment impossible at the database level. An asset is in at most
    one zone; absence of a row means UNKNOWN."""

    __tablename__ = "network_zone_assignments"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_nza_id_org"),
        UniqueConstraint("organization_id", "asset_id", name="ux_nza_org_asset"),
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["ai_assets.id", "ai_assets.organization_id"],
            name="fk_nza_same_tenant_asset",
            ondelete="CASCADE",
        ),
        Index("ix_nza_org_zone", "organization_id", "zone_type"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(26), nullable=False)
    zone_type: Mapped[str] = mapped_column(String(20), nullable=False)
    note: Mapped[str] = mapped_column(String(500), nullable=False, server_default=text("''"))
    assigned_by: Mapped[str] = mapped_column(String(26), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
