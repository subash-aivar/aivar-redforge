"""ORM model for credential_vault_rotation_policies."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import Boolean, DateTime, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class RotationPolicyModel(Base):
    __tablename__ = "credential_vault_rotation_policies"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    interval_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    max_versions_kept: Mapped[int] = mapped_column(Integer, nullable=False)
    notify_days_before: Mapped[int] = mapped_column(Integer, nullable=False)
    auto_rotate: Mapped[bool] = mapped_column(Boolean, nullable=False)
    auto_commit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    commit_window_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        UniqueConstraint("tenant_id", "name", name="uq_cv_rotation_policies_tenant_name"),
    )
