"""SQLAlchemy models for M26 cloud_security schema foundation tables."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base

_SCHEMA = "cloud_security"


class CloudProviderModel(Base):
    __tablename__ = "cloud_providers"
    __table_args__ = (
        UniqueConstraint(
            "organization_id",
            "provider_type",
            name="uq_cloud_providers_org_type",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    provider_type: Mapped[str] = mapped_column(String(16), nullable=False)
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    discovery_config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class CloudAccountModel(Base):
    __tablename__ = "cloud_accounts"
    __table_args__ = (
        UniqueConstraint(
            "cloud_provider_id",
            "external_id",
            name="uq_cloud_accounts_provider_external",
        ),
        {"schema": _SCHEMA},
    )

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    cloud_provider_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey(f"{_SCHEMA}.cloud_providers.id"),
        nullable=False,
        index=True,
    )
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    external_id: Mapped[str] = mapped_column(String(256), nullable=False)
    display_name: Mapped[str] = mapped_column(String(256), nullable=False)
    account_type: Mapped[str] = mapped_column(String(32), nullable=False)
    regions: Mapped[list[Any]] = mapped_column(JSONB, nullable=False, default=list)
    credential_ref: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    sync_state: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    account_metadata: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict
    )
    tags: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
