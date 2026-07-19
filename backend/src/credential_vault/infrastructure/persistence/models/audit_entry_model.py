"""ORM model for credential_vault_audit_entries."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class AuditEntryModel(Base):
    __tablename__ = "credential_vault_audit_entries"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    audit_log_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    credential_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    operation: Mapped[str] = mapped_column(String(64), nullable=False)
    outcome: Mapped[str] = mapped_column(String(32), nullable=False)
    principal_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    state_before: Mapped[str | None] = mapped_column(String(32), nullable=True)
    state_after: Mapped[str | None] = mapped_column(String(32), nullable=True)

    __table_args__ = (
        Index(
            "ix_cv_audit_entries_log_occurred",
            "audit_log_id",
            "occurred_at",
        ),
        Index(
            "ix_cv_audit_entries_cred_tenant",
            "credential_id",
            "tenant_id",
        ),
    )
