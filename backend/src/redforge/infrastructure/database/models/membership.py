"""SQLAlchemy ORM model for the Membership table.

Memberships are the tenant-isolation security boundary: every
organization-scoped request is authorized against a row in this table.
Given that role, this uses real indexed columns (not the JSONB document
pattern used elsewhere) — the lookup on (user_id, organization_id) is on
the hot path of every authenticated request and must be a fast, indexed
equality lookup, not a JSONB scan.
"""

from datetime import datetime

from sqlalchemy import DateTime, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class MembershipModel(Base):
    """ORM representation of a Membership (User ↔ Organization ↔ Role).

    `status` (active/suspended/removed) replaced the original `is_active`
    boolean in migration 0006 — see that migration's docstring for why a
    3-state column was needed (suspend/reactivate is a distinct,
    reversible lifecycle transition from remove, which is terminal).
    """

    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("user_id", "organization_id", name="uq_membership_user_org"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
