"""SQLAlchemy ORM models for the Security Correlation foundation — M9."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKeyConstraint, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from redforge.infrastructure.database.base import Base


class SecurityCorrelationModel(Base):
    __tablename__ = "security_correlations"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="ux_sec_correlations_id_org"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    stable_rule_id: Mapped[str] = mapped_column(String(100), nullable=False)
    rule_version: Mapped[int] = mapped_column(Integer, nullable=False)
    identity_key: Mapped[str] = mapped_column(String(600), nullable=False)
    evidence_state: Mapped[str] = mapped_column(String(20), nullable=False)
    lifecycle: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    summary: Mapped[str] = mapped_column(String(1000), nullable=False)
    operator_action: Mapped[str] = mapped_column(String(1000), nullable=False, default="")
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)


class SecurityCorrelationConditionModel(Base):
    __tablename__ = "security_correlation_conditions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["correlation_id", "organization_id"],
            ["security_correlations.id", "security_correlations.organization_id"],
            name="fk_sec_corr_cond_correlation_same_tenant",
        ),
        ForeignKeyConstraint(
            ["security_condition_id", "organization_id"],
            ["security_conditions.id", "security_conditions.organization_id"],
            name="fk_sec_corr_cond_condition_same_tenant",
        ),
        UniqueConstraint("correlation_id", "security_condition_id", name="ux_sec_corr_cond_pair"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    security_condition_id: Mapped[str] = mapped_column(String(26), nullable=False)


class SecurityCorrelationEntityModel(Base):
    __tablename__ = "security_correlation_entities"
    __table_args__ = (
        ForeignKeyConstraint(
            ["correlation_id", "organization_id"],
            ["security_correlations.id", "security_correlations.organization_id"],
            name="fk_sec_corr_entity_correlation_same_tenant",
        ),
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["ai_assets.id", "ai_assets.organization_id"],
            name="fk_sec_corr_entity_asset_same_tenant",
        ),
        UniqueConstraint("correlation_id", "asset_id", name="ux_sec_corr_entity_pair"),
    )

    id: Mapped[str] = mapped_column(String(26), primary_key=True)
    correlation_id: Mapped[str] = mapped_column(String(26), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(26), nullable=False)
    asset_id: Mapped[str] = mapped_column(String(26), nullable=False)
