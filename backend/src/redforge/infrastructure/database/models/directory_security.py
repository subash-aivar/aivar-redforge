"""SQLAlchemy ORM models for the Directory Security foundation — M5."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKeyConstraint,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class DirectoryIdentityModel(Base):
    __tablename__ = "directory_identities"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_dir_identities_id_org"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    connector_id: Mapped[str] = mapped_column(String(26), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    principal_category: Mapped[str] = mapped_column(String(20), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    principal_name: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    source_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    privilege_classification: Mapped[str] = mapped_column(String(20), nullable=False)
    privilege_reason: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    observation_lifecycle: Mapped[str] = mapped_column(String(20), nullable=False)
    safe_attributes: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class DirectoryGroupModel(Base):
    __tablename__ = "directory_groups"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_dir_groups_id_org"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    connector_id: Mapped[str] = mapped_column(String(26), nullable=False)
    external_id: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    is_recognized_privileged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class DirectoryMembershipModel(Base):
    __tablename__ = "directory_memberships"
    __table_args__ = (
        ForeignKeyConstraint(
            ["identity_id", "organization_id"],
            ["directory_identities.id", "directory_identities.organization_id"],
            name="fk_dir_membership_identity_same_tenant",
        ),
        ForeignKeyConstraint(
            ["group_id", "organization_id"],
            ["directory_groups.id", "directory_groups.organization_id"],
            name="fk_dir_membership_group_same_tenant",
        ),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    identity_id: Mapped[str] = mapped_column(String(26), nullable=False)
    group_id: Mapped[str] = mapped_column(String(26), nullable=False)
    provenance: Mapped[str] = mapped_column(String(100), nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
