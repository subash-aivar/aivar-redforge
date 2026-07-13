"""SQLAlchemy ORM model for the Organization table.

This model is a pure persistence concern. It maps directly to a database
table and has no business logic. The mapper layer handles conversion
between this ORM model and the domain entity.
"""

from datetime import datetime

from sqlalchemy import DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class OrganizationModel(Base):
    """ORM representation of an Organization.

    Table: organizations
    """

    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    slug: Mapped[str] = mapped_column(String(63), unique=True, nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    plan: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
