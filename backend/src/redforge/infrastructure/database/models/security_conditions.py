"""SQLAlchemy ORM model for the Security Condition foundation — M8."""

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKeyConstraint, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class SecurityConditionModel(Base):
    __tablename__ = "security_conditions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["affected_asset_id", "organization_id"],
            ["ai_assets.id", "ai_assets.organization_id"],
            name="fk_sec_condition_asset_same_tenant",
        ),
        UniqueConstraint("id", "organization_id", name="ux_sec_conditions_id_org"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    affected_asset_id: Mapped[str] = mapped_column(String(26), nullable=False)
    source_category: Mapped[str] = mapped_column(String(30), nullable=False)
    stable_rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    qualifier: Mapped[str] = mapped_column(String(100), nullable=False, default="")
    identity_key: Mapped[str] = mapped_column(String(400), nullable=False)
    evidence_state: Mapped[str] = mapped_column(String(20), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(String(1000), nullable=False)
    remediation: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    canonical_references: Mapped[list[str]] = mapped_column(JSON, nullable=False)
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False)
    lifecycle: Mapped[str] = mapped_column(String(20), nullable=False)
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
