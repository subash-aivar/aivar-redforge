"""ORM model for credential_vault_credentials."""

from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class CredentialModel(Base):
    __tablename__ = "credential_vault_credentials"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    cred_category: Mapped[str] = mapped_column(String(64), nullable=False)
    cred_subtype: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    owner_principal_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    active_version_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    rotation_policy_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    expiration_policy_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    vault_backend_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "name",
            name="uq_credential_vault_credentials_tenant_name",
        ),
        Index("ix_cv_credentials_tenant_state", "tenant_id", "state"),
        Index("ix_cv_credentials_rotation_policy", "tenant_id", "rotation_policy_id"),
        Index(
            "ix_cv_credentials_expiration_policy",
            "tenant_id",
            "expiration_policy_id",
        ),
    )
