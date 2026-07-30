"""PgAssetRepository — SQLAlchemy implementation of the
`IAssetRepository` async ABC port (M49C), matching
`risk_engine.infrastructure.persistence.repositories.
pg_risk_profile_repository.PgEnterpriseRiskProfileRepository`'s
pattern exactly: every DB call is `await`ed, no synchronous
`Session`/`psycopg` involved anywhere.

No optimistic-locking version check is performed on `save()`: like
`EnterpriseRiskProfile`, the frozen `Asset` aggregate carries no
`version`/`row_version` field a caller could have loaded and compared
against — inventing one would mean reopening the frozen M49A
aggregate. `row_version` is still persisted and bumped on every write
(useful for auditing/debugging), but `save()` here is last-writer-wins
at the row level, exactly like every attack_surface_management command
already is at the aggregate level (the frozen M49B application
services always `get()` then mutate then `save()` within a single unit
of work).

Domain events are never persisted here: `Asset.pop_events()` exists
for a caller to drain and hand to an `IEventPublisher`, but no frozen
M49B application service actually calls `pop_events()`/
`publish_batch()` — matching risk_engine's own current convention
exactly (events are drained-and-published nowhere yet in that context
either), so this repository does not invent an event-store table the
platform doesn't otherwise have.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import structlog
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from attack_surface_management.application.ports.i_asset_repository import IAssetRepository
from attack_surface_management.domain.aggregates.asset import Asset
from attack_surface_management.domain.entities.certificate import Certificate
from attack_surface_management.domain.entities.dns_record import DnsRecordEntry
from attack_surface_management.domain.entities.open_port import OpenPort
from attack_surface_management.domain.value_objects.asset_ownership import AssetOwnership
from attack_surface_management.domain.value_objects.domain_name import DomainName, Subdomain
from attack_surface_management.domain.value_objects.enums import (
    AssetClassification,
    AssetLifecycleState,
    AssetType,
    CertificateStatus,
    Criticality,
    DiscoverySource,
    DnsRecordType,
    ExposureState,
    PortProtocol,
    PortState,
)
from attack_surface_management.domain.value_objects.identifiers import (
    AssetId,
    CertificateId,
    DnsRecordId,
    PortId,
    TenantId,
)
from attack_surface_management.domain.value_objects.ip_address import IPAddress
from attack_surface_management.domain.value_objects.service_banner import ServiceBanner
from attack_surface_management.domain.value_objects.technology_fingerprint import (
    TechnologyFingerprint,
)
from attack_surface_management.infrastructure.persistence.exceptions import (
    AttackSurfaceIntegrityError,
)
from attack_surface_management.infrastructure.persistence.mappers import new_uuid
from attack_surface_management.infrastructure.persistence.models.asset_model import (
    AssetCertificateModel,
    AssetDnsRecordModel,
    AssetFingerprintModel,
    AssetModel,
    AssetPortModel,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.ext.asyncio import AsyncSession

_logger = structlog.get_logger("attack_surface_management.infrastructure.persistence")


def _row_to_asset(row: AssetModel) -> Asset:
    domain_name = DomainName(row.domain_name) if row.domain_name else None
    subdomain = None
    if row.subdomain_fqdn is not None and row.subdomain_parent is not None:
        subdomain = Subdomain(fqdn=row.subdomain_fqdn, parent=DomainName(row.subdomain_parent))
    ip_address = IPAddress(row.ip_address) if row.ip_address else None
    ownership = None
    if row.ownership_owning_team is not None:
        ownership = AssetOwnership(
            owning_team=row.ownership_owning_team, contact=row.ownership_contact
        )

    ports = tuple(
        OpenPort(
            port_id=PortId(p.id),
            port_number=p.port_number,
            protocol=PortProtocol(p.protocol),
            state=PortState(p.state),
            detected_at=p.detected_at,
            service=(
                ServiceBanner(
                    name=p.service_name, version=p.service_version, banner=p.service_banner
                )
                if p.service_name
                else None
            ),
        )
        for p in row.ports
    )
    certificates = tuple(
        Certificate(
            certificate_id=CertificateId(c.id),
            common_name=c.common_name,
            issuer=c.issuer,
            serial_number=c.serial_number,
            not_before=c.not_before,
            not_after=c.not_after,
            status=CertificateStatus(c.status),
        )
        for c in row.certificates
    )
    dns_records = tuple(
        DnsRecordEntry(
            record_id=DnsRecordId(d.id),
            record_type=DnsRecordType(d.record_type),
            name=d.name,
            value=d.value,
            ttl_seconds=d.ttl_seconds,
            detected_at=d.detected_at,
        )
        for d in row.dns_records
    )
    fingerprints = tuple(
        TechnologyFingerprint(name=f.name, version=f.version, confidence=f.confidence)
        for f in sorted(row.fingerprints, key=lambda f: f.ordinal)
    )

    return Asset(
        asset_id=AssetId(row.id),
        tenant_id=TenantId.from_uuid(row.tenant_id),
        asset_type=AssetType(row.asset_type),
        created_at=row.created_at,
        domain_name=domain_name,
        subdomain=subdomain,
        ip_address=ip_address,
        discovery_source=DiscoverySource(row.discovery_source),
        classification=AssetClassification(row.classification),
        criticality=Criticality(row.criticality),
        exposure_state=ExposureState(row.exposure_state),
        lifecycle_state=AssetLifecycleState(row.lifecycle_state),
        ownership=ownership,
        ports=ports,
        certificates=certificates,
        dns_records=dns_records,
        fingerprints=fingerprints,
        updated_at=row.updated_at,
    )


class PgAssetRepository(IAssetRepository):
    """Tenant-scoped, transaction-bound async SQLAlchemy repository for
    `Asset`."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save(self, asset: Asset) -> None:
        try:
            await self._save(asset)
        except IntegrityError as exc:
            await self._session.rollback()
            raise AttackSurfaceIntegrityError("save Asset", str(exc.orig)) from exc
        except SQLAlchemyError as exc:
            await self._session.rollback()
            raise AttackSurfaceIntegrityError("save Asset", str(exc)) from exc

    async def _save(self, asset: Asset) -> None:
        asset_uuid = asset.asset_id.value
        tenant_uuid = asset.tenant_id.value.to_uuid()

        row = await self._session.get(AssetModel, asset_uuid)
        if row is None:
            row = AssetModel(
                id=asset_uuid,
                tenant_id=tenant_uuid,
                asset_type=asset.asset_type.value,
                domain_name=str(asset.domain_name) if asset.domain_name else None,
                subdomain_fqdn=str(asset.subdomain) if asset.subdomain else None,
                subdomain_parent=(
                    str(asset.subdomain.parent) if asset.subdomain is not None else None
                ),
                ip_address=str(asset.ip_address) if asset.ip_address else None,
                discovery_source=asset.discovery_source.value,
                classification=asset.classification.value,
                criticality=asset.criticality.value,
                exposure_state=asset.exposure_state.value,
                lifecycle_state=asset.lifecycle_state.value,
                ownership_owning_team=(
                    asset.ownership.owning_team if asset.ownership is not None else None
                ),
                ownership_contact=(
                    asset.ownership.contact if asset.ownership is not None else None
                ),
                created_at=asset.created_at,
                updated_at=asset.updated_at,
                row_version=1,
            )
            self._session.add(row)
            await self._session.flush()
        else:
            row.asset_type = asset.asset_type.value
            row.domain_name = str(asset.domain_name) if asset.domain_name else None
            row.subdomain_fqdn = str(asset.subdomain) if asset.subdomain else None
            row.subdomain_parent = (
                str(asset.subdomain.parent) if asset.subdomain is not None else None
            )
            row.ip_address = str(asset.ip_address) if asset.ip_address else None
            row.discovery_source = asset.discovery_source.value
            row.classification = asset.classification.value
            row.criticality = asset.criticality.value
            row.exposure_state = asset.exposure_state.value
            row.lifecycle_state = asset.lifecycle_state.value
            row.ownership_owning_team = (
                asset.ownership.owning_team if asset.ownership is not None else None
            )
            row.ownership_contact = asset.ownership.contact if asset.ownership is not None else None
            row.updated_at = asset.updated_at
            row.row_version = row.row_version + 1

        # Full replace of every child collection: each entity/value in
        # these tuples has no independent write path outside of the
        # aggregate re-saving its whole current state (mirrors
        # RiskProfileContributionModel's delete-then-insert pattern).
        await self._session.execute(
            delete(AssetPortModel).where(AssetPortModel.asset_id == asset_uuid)
        )
        for port in asset.ports:
            self._session.add(
                AssetPortModel(
                    id=port.port_id.value,
                    asset_id=asset_uuid,
                    port_number=port.port_number,
                    protocol=port.protocol.value,
                    state=port.state.value,
                    detected_at=port.detected_at,
                    service_name=port.service.name if port.service else None,
                    service_version=port.service.version if port.service else None,
                    service_banner=port.service.banner if port.service else None,
                )
            )

        await self._session.execute(
            delete(AssetCertificateModel).where(AssetCertificateModel.asset_id == asset_uuid)
        )
        for certificate in asset.certificates:
            self._session.add(
                AssetCertificateModel(
                    id=certificate.certificate_id.value,
                    asset_id=asset_uuid,
                    common_name=certificate.common_name,
                    issuer=certificate.issuer,
                    serial_number=certificate.serial_number,
                    not_before=certificate.not_before,
                    not_after=certificate.not_after,
                    status=certificate.status.value,
                )
            )

        await self._session.execute(
            delete(AssetDnsRecordModel).where(AssetDnsRecordModel.asset_id == asset_uuid)
        )
        for record in asset.dns_records:
            self._session.add(
                AssetDnsRecordModel(
                    id=record.record_id.value,
                    asset_id=asset_uuid,
                    record_type=record.record_type.value,
                    name=record.name,
                    value=record.value,
                    ttl_seconds=record.ttl_seconds,
                    detected_at=record.detected_at,
                )
            )

        await self._session.execute(
            delete(AssetFingerprintModel).where(AssetFingerprintModel.asset_id == asset_uuid)
        )
        for ordinal, fingerprint in enumerate(asset.fingerprints):
            self._session.add(
                AssetFingerprintModel(
                    id=new_uuid(),
                    asset_id=asset_uuid,
                    ordinal=ordinal,
                    name=fingerprint.name,
                    version=fingerprint.version,
                    confidence=fingerprint.confidence,
                )
            )

        await self._session.flush()
        _logger.info(
            "asset_saved",
            asset_id=str(asset.asset_id),
            tenant_id=str(asset.tenant_id),
            lifecycle_state=asset.lifecycle_state.value,
            port_count=len(asset.ports),
        )

    async def get(self, tenant_id: TenantId, asset_id: AssetId) -> Asset | None:
        row = await self._session.get(AssetModel, asset_id.value)
        if row is None:
            return None
        if row.tenant_id != tenant_id.value.to_uuid():
            # Tenant-isolation: an asset that exists under a different
            # tenant must never be distinguishable from "doesn't exist".
            return None
        return _row_to_asset(row)

    async def list(self, tenant_id: TenantId, **filters: object) -> Sequence[Asset]:
        stmt = select(AssetModel).where(AssetModel.tenant_id == tenant_id.value.to_uuid())

        asset_type = filters.get("asset_type")
        if asset_type is not None:
            value = asset_type.value if isinstance(asset_type, AssetType) else asset_type
            stmt = stmt.where(AssetModel.asset_type == value)

        classification = filters.get("classification")
        if classification is not None:
            value = (
                classification.value
                if isinstance(classification, AssetClassification)
                else classification
            )
            stmt = stmt.where(AssetModel.classification == value)

        criticality = filters.get("criticality")
        if criticality is not None:
            value = criticality.value if isinstance(criticality, Criticality) else criticality
            stmt = stmt.where(AssetModel.criticality == value)

        exposure_state = filters.get("exposure_state")
        if exposure_state is not None:
            value = (
                exposure_state.value
                if isinstance(exposure_state, ExposureState)
                else exposure_state
            )
            stmt = stmt.where(AssetModel.exposure_state == value)

        lifecycle_state = filters.get("lifecycle_state")
        if lifecycle_state is not None:
            value = (
                lifecycle_state.value
                if isinstance(lifecycle_state, AssetLifecycleState)
                else lifecycle_state
            )
            stmt = stmt.where(AssetModel.lifecycle_state == value)

        stmt = stmt.order_by(AssetModel.created_at.desc())

        limit = filters.get("limit")
        offset = filters.get("offset")
        if isinstance(offset, int):
            stmt = stmt.offset(offset)
        if isinstance(limit, int):
            stmt = stmt.limit(limit)

        result = await self._session.execute(stmt)
        rows = result.scalars().all()
        return [_row_to_asset(row) for row in rows]
