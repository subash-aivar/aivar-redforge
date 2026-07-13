"""SQLAlchemy ORM models for the Platform Identity bounded context."""

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class PlatformAssignmentModel(Base):
    """ORM representation of a PlatformAssignment.

    Race-safety for "no duplicate active grant" and for bootstrap is
    enforced by database constraints/migration, not by application-level
    count-then-insert logic — see migration 0011 for the partial unique
    index and the platform_bootstrap_state atomic-claim table.
    """

    __tablename__ = "platform_assignments"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    granted_by: Mapped[str] = mapped_column(String(26), nullable=False)
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_by: Mapped[str | None] = mapped_column(String(26), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class PlatformBootstrapStateModel(Base):
    """Singleton row used to atomically claim the one-time Super Admin
    bootstrap. Exactly one row exists (id='singleton'), seeded by the
    migration. See PlatformAccessService.bootstrap_super_admin for the
    atomic UPDATE ... WHERE consumed_at IS NULL RETURNING claim pattern.
    """

    __tablename__ = "platform_bootstrap_state"

    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    consumed_by: Mapped[str | None] = mapped_column(String(26), nullable=True)


class PlatformAuditLogModel(Base):
    """Append-only platform security audit log.

    Honest terminology: this is an append-only application audit table
    enforced by convention (the repository never exposes update/delete),
    not a cryptographically-immutable ledger. No genuinely immutable
    storage layer exists in this deployment, so no stronger claim is made.
    """

    __tablename__ = "platform_audit_log"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False)
    role: Mapped[str | None] = mapped_column(String(50), nullable=True)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    correlation_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    metadata_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True,
    )
