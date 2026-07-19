"""ORM model for credential_vault_versions."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Index, Integer, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class CredentialVersionModel(Base):
    __tablename__ = "credential_vault_versions"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    credential_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False, index=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    version_state: Mapped[str] = mapped_column(String(32), nullable=False)
    created_by: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    cipher_algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    iv: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    tag: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    payload_size: Mapped[int] = mapped_column(Integer, nullable=False)
    wrapped_dek: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    master_key_id: Mapped[str] = mapped_column(String(256), nullable=False)
    wrapping_algorithm: Mapped[str] = mapped_column(String(64), nullable=False)
    key_created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rotation_trigger: Mapped[str | None] = mapped_column(String(64), nullable=True)
    rotation_prev_version_id: Mapped[UUID | None] = mapped_column(
        PgUUID(as_uuid=True), nullable=True
    )
    rotation_policy_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    rotation_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    __table_args__ = (
        Index(
            "ix_cv_versions_cred_state",
            "credential_id",
            "tenant_id",
            "version_state",
        ),
        Index(
            "ix_cv_versions_cred_number",
            "credential_id",
            "tenant_id",
            "version_number",
        ),
    )
