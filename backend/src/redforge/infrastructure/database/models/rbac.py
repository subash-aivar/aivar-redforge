"""SQLAlchemy ORM models for the RBAC bounded context — M17.

See migration 0026's own docstring for the reuse-vs-new rationale.
"""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    PrimaryKeyConstraint,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class OrganizationRoleModel(Base):
    __tablename__ = "organization_roles"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_org_roles_id_org"),
        UniqueConstraint(
            "organization_id", "normalized_name", name="ux_org_roles_org_normalized_name"
        ),
        Index("ix_org_roles_organization_id", "organization_id"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    normalized_name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OrganizationRolePermissionModel(Base):
    __tablename__ = "organization_role_permissions"
    __table_args__ = (
        PrimaryKeyConstraint("role_id", "permission", name="pk_org_role_permissions"),
        ForeignKeyConstraint(
            ["role_id"], ["organization_roles.id"],
            name="fk_org_role_permissions_role", ondelete="CASCADE",
        ),
    )

    role_id: Mapped[str] = mapped_column(String(26))
    permission: Mapped[str] = mapped_column(String(100))


class OrganizationGroupModel(Base):
    __tablename__ = "organization_groups"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_org_groups_id_org"),
        UniqueConstraint(
            "organization_id", "normalized_name", name="ux_org_groups_org_normalized_name"
        ),
        Index("ix_org_groups_organization_id", "organization_id"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    normalized_name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OrganizationGroupMembershipModel(Base):
    __tablename__ = "organization_group_memberships"
    __table_args__ = (
        UniqueConstraint("group_id", "user_id", name="ux_group_memberships_group_user"),
        ForeignKeyConstraint(
            ["group_id", "organization_id"],
            ["organization_groups.id", "organization_groups.organization_id"],
            name="fk_group_memberships_same_tenant_group", ondelete="CASCADE",
        ),
        Index("ix_group_memberships_org_user", "organization_id", "user_id"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    group_id: Mapped[str] = mapped_column(String(26), nullable=False)
    user_id: Mapped[str] = mapped_column(String(26), nullable=False)
    added_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OrganizationGroupRoleModel(Base):
    __tablename__ = "organization_group_roles"
    __table_args__ = (
        UniqueConstraint("group_id", "role_id", name="ux_group_roles_group_role"),
        ForeignKeyConstraint(
            ["group_id", "organization_id"],
            ["organization_groups.id", "organization_groups.organization_id"],
            name="fk_group_roles_same_tenant_group", ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["role_id", "organization_id"],
            ["organization_roles.id", "organization_roles.organization_id"],
            name="fk_group_roles_same_tenant_role", ondelete="CASCADE",
        ),
        Index("ix_group_roles_org_group", "organization_id", "group_id"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    group_id: Mapped[str] = mapped_column(String(26), nullable=False)
    role_id: Mapped[str] = mapped_column(String(26), nullable=False)
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OrganizationUserRoleModel(Base):
    __tablename__ = "organization_user_roles"
    __table_args__ = (
        UniqueConstraint(
            "organization_id", "user_id", "role_id", name="ux_user_roles_org_user_role"
        ),
        ForeignKeyConstraint(
            ["role_id", "organization_id"],
            ["organization_roles.id", "organization_roles.organization_id"],
            name="fk_user_roles_same_tenant_role", ondelete="CASCADE",
        ),
        Index("ix_user_roles_org_user", "organization_id", "user_id"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    user_id: Mapped[str] = mapped_column(String(26), nullable=False)
    role_id: Mapped[str] = mapped_column(String(26), nullable=False)
    assigned_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class OrganizationAdminAuditLogModel(Base):
    __tablename__ = "organization_admin_audit_log"
    __table_args__ = (
        Index("ix_org_admin_audit_org_occurred", "organization_id", "occurred_at"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(26), nullable=False)
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    target_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_id: Mapped[str] = mapped_column(String(26), nullable=False)
    metadata_: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
