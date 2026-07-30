"""ORM models for the `Asset` aggregate (M49C).

Four tables, mirroring `risk_engine.infrastructure.persistence.models.
risk_profile_model`'s one-root-plus-child-tables shape:

- ``attack_surface_assets`` — the aggregate root row (one per `Asset`),
  holding its declared identifier value objects (`DomainName`,
  `Subdomain`, `IPAddress`) and `AssetOwnership` denormalized as
  scalar columns (mirrors `RiskProfileModel`'s denormalization of
  `CompositeRiskScore` onto its owning row).
- ``attack_surface_asset_ports`` — child rows for the aggregate's
  `ports` tuple (`OpenPort` entities, individually identified).
- ``attack_surface_asset_certificates`` — child rows for the
  aggregate's `certificates` tuple (`Certificate` entities).
- ``attack_surface_asset_dns_records`` — child rows for the
  aggregate's `dns_records` tuple (`DnsRecordEntry` entities).
- ``attack_surface_asset_fingerprints`` — child rows for the
  aggregate's `fingerprints` tuple (`TechnologyFingerprint` value
  objects — identity-less, so this table is rebuilt in full on every
  `save()`, exactly like `RiskProfileContributionModel`).

All child collections use `lazy="selectin"` — mandatory under
`AsyncSession` (see the module note in `risk_profile_model.py`): the
default `lazy="select"` issues an implicit lazy-load query the first
time the attribute is accessed, which raises `MissingGreenlet` outside
an awaited context. `selectin` eager-loads via an additional awaited
SELECT as part of the parent query.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from redforge.infrastructure.database.base import Base


class AssetModel(Base):
    __tablename__ = "attack_surface_assets"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    tenant_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(32), nullable=False)

    domain_name: Mapped[str | None] = mapped_column(String(253), nullable=True)
    subdomain_fqdn: Mapped[str | None] = mapped_column(String(253), nullable=True)
    subdomain_parent: Mapped[str | None] = mapped_column(String(253), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)

    discovery_source: Mapped[str] = mapped_column(String(32), nullable=False)
    classification: Mapped[str] = mapped_column(String(32), nullable=False)
    criticality: Mapped[str] = mapped_column(String(32), nullable=False)
    exposure_state: Mapped[str] = mapped_column(String(32), nullable=False)
    lifecycle_state: Mapped[str] = mapped_column(String(32), nullable=False)

    ownership_owning_team: Mapped[str | None] = mapped_column(String(256), nullable=True)
    ownership_contact: Mapped[str | None] = mapped_column(String(256), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    row_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)

    ports: Mapped[list[AssetPortModel]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    certificates: Mapped[list[AssetCertificateModel]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    dns_records: Mapped[list[AssetDnsRecordModel]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    fingerprints: Mapped[list[AssetFingerprintModel]] = relationship(
        back_populates="asset",
        cascade="all, delete-orphan",
        order_by="AssetFingerprintModel.ordinal",
        lazy="selectin",
    )

    __table_args__ = (
        Index("ix_attack_surface_assets_tenant", "tenant_id"),
        Index("ix_attack_surface_assets_tenant_type", "tenant_id", "asset_type"),
        Index("ix_attack_surface_assets_tenant_lifecycle", "tenant_id", "lifecycle_state"),
    )


class AssetPortModel(Base):
    __tablename__ = "attack_surface_asset_ports"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    asset_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("attack_surface_assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    port_number: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(16), nullable=False)
    state: Mapped[str] = mapped_column(String(16), nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    service_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    service_version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    service_banner: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    asset: Mapped[AssetModel] = relationship(back_populates="ports")

    __table_args__ = (Index("ix_attack_surface_asset_ports_asset", "asset_id"),)


class AssetCertificateModel(Base):
    __tablename__ = "attack_surface_asset_certificates"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    asset_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("attack_surface_assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    common_name: Mapped[str] = mapped_column(String(512), nullable=False)
    issuer: Mapped[str] = mapped_column(String(512), nullable=False)
    serial_number: Mapped[str] = mapped_column(String(256), nullable=False)
    not_before: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    not_after: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)

    asset: Mapped[AssetModel] = relationship(back_populates="certificates")

    __table_args__ = (Index("ix_attack_surface_asset_certificates_asset", "asset_id"),)


class AssetDnsRecordModel(Base):
    __tablename__ = "attack_surface_asset_dns_records"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    asset_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("attack_surface_assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    record_type: Mapped[str] = mapped_column(String(16), nullable=False)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    ttl_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    asset: Mapped[AssetModel] = relationship(back_populates="dns_records")

    __table_args__ = (Index("ix_attack_surface_asset_dns_records_asset", "asset_id"),)


class AssetFingerprintModel(Base):
    """`TechnologyFingerprint` is identity-less (a plain value object,
    not an entity — see `technology_fingerprint.py`), so this child
    table is rebuilt in full (delete-then-insert) on every `save()`,
    exactly like `RiskProfileContributionModel`."""

    __tablename__ = "attack_surface_asset_fingerprints"

    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    asset_id: Mapped[UUID] = mapped_column(
        PgUUID(as_uuid=True),
        ForeignKey("attack_surface_assets.id", ondelete="CASCADE"),
        nullable=False,
    )
    ordinal: Mapped[int] = mapped_column(Integer, nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    version: Mapped[str | None] = mapped_column(String(128), nullable=True)
    confidence: Mapped[float] = mapped_column(Float(), nullable=False)

    asset: Mapped[AssetModel] = relationship(back_populates="fingerprints")

    __table_args__ = (
        Index("ix_attack_surface_asset_fingerprints_asset", "asset_id"),
        UniqueConstraint(
            "asset_id", "ordinal", name="uq_attack_surface_asset_fingerprints_ordinal"
        ),
    )
