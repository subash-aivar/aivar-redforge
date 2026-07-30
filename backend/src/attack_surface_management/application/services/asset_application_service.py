"""AssetApplicationService — the M49B application service orchestrating
every `Asset` command. Never performs domain computation itself:
construction is delegated to `AssetFactory`, exposure classification to
`ExposureEvaluationService`/`ExposureClassificationPolicy`, criticality
scoring to `CriticalityScoringService`/`CriticalityScoringPolicy`, and
every state transition to the aggregate's own methods. Returns DTOs
only — no domain object ever crosses this boundary. Constructor-
injected, ABC-typed collaborators only (`IAssetRepository` +
`IUnitOfWork`) — no concrete infrastructure."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from attack_surface_management.application.dtos.asset_dto import (
    AssetDTO,
    AssetOwnershipDTO,
    CertificateDTO,
    CriticalityScoreDTO,
    DnsRecordDTO,
    OpenPortDTO,
    TechnologyFingerprintDTO,
)
from attack_surface_management.application.exceptions import (
    AssetNotFoundError,
    AssetTenantIsolationViolationError,
)
from attack_surface_management.application.services.command_validation import (
    validate_asset_identifier_present,
)
from attack_surface_management.domain.entities.certificate import Certificate
from attack_surface_management.domain.entities.dns_record import DnsRecordEntry
from attack_surface_management.domain.entities.open_port import OpenPort
from attack_surface_management.domain.factories.asset_factory import AssetFactory
from attack_surface_management.domain.services.criticality_scoring_service import (
    CriticalityScoringService,
)
from attack_surface_management.domain.services.exposure_evaluation_service import (
    ExposureEvaluationService,
)
from attack_surface_management.domain.value_objects.asset_ownership import AssetOwnership
from attack_surface_management.domain.value_objects.enums import DiscoverySource, PortState
from attack_surface_management.domain.value_objects.identifiers import (
    CertificateId,
    DnsRecordId,
    PortId,
)
from attack_surface_management.domain.value_objects.technology_fingerprint import (
    TechnologyFingerprint,
)

if TYPE_CHECKING:
    from attack_surface_management.application.commands.asset_commands import (
        AddDnsRecordCommand,
        AddTechnologyFingerprintCommand,
        AttachCertificateCommand,
        ClosePortCommand,
        DecommissionAssetCommand,
        EvaluateExposureCommand,
        ReclassifyAssetCommand,
        RecomputeCriticalityScoreCommand,
        RecordOpenPortCommand,
        RegisterAssetCommand,
        RemoveDnsRecordCommand,
        RevokeCertificateCommand,
        SetCriticalityCommand,
        TransitionAssetLifecycleCommand,
        UpdateOwnershipCommand,
    )
    from attack_surface_management.application.ports.i_asset_repository import IAssetRepository
    from attack_surface_management.application.ports.i_unit_of_work import IUnitOfWork
    from attack_surface_management.domain.aggregates.asset import Asset
    from attack_surface_management.domain.value_objects.identifiers import AssetId, TenantId


def _port_to_dto(port: OpenPort) -> OpenPortDTO:
    return OpenPortDTO(
        port_id=str(port.port_id),
        port_number=port.port_number,
        protocol=port.protocol.value,
        state=port.state.value,
        detected_at=port.detected_at,
        is_high_risk=port.is_high_risk,
        service_name=port.service.name if port.service else None,
        service_version=port.service.version if port.service else None,
    )


def _certificate_to_dto(certificate: Certificate) -> CertificateDTO:
    return CertificateDTO(
        certificate_id=str(certificate.certificate_id),
        common_name=certificate.common_name,
        issuer=certificate.issuer,
        serial_number=certificate.serial_number,
        not_before=certificate.not_before,
        not_after=certificate.not_after,
        status=certificate.status.value,
    )


def _dns_record_to_dto(record: DnsRecordEntry) -> DnsRecordDTO:
    return DnsRecordDTO(
        record_id=str(record.record_id),
        record_type=record.record_type.value,
        name=record.name,
        value=record.value,
        ttl_seconds=record.ttl_seconds,
        detected_at=record.detected_at,
    )


def _fingerprint_to_dto(fingerprint: TechnologyFingerprint) -> TechnologyFingerprintDTO:
    return TechnologyFingerprintDTO(
        name=fingerprint.name,
        version=fingerprint.version,
        confidence=fingerprint.confidence,
    )


def asset_to_dto(asset: Asset) -> AssetDTO:
    return AssetDTO(
        asset_id=str(asset.asset_id),
        tenant_id=str(asset.tenant_id),
        asset_type=asset.asset_type.value,
        primary_identifier=asset.primary_identifier,
        discovery_source=asset.discovery_source.value,
        classification=asset.classification.value,
        criticality=asset.criticality.value,
        exposure_state=asset.exposure_state.value,
        lifecycle_state=asset.lifecycle_state.value,
        created_at=asset.created_at,
        updated_at=asset.updated_at,
        domain_name=str(asset.domain_name) if asset.domain_name else None,
        subdomain=str(asset.subdomain) if asset.subdomain else None,
        ip_address=str(asset.ip_address) if asset.ip_address else None,
        ownership=(
            AssetOwnershipDTO(
                owning_team=asset.ownership.owning_team, contact=asset.ownership.contact
            )
            if asset.ownership is not None
            else None
        ),
        ports=tuple(_port_to_dto(p) for p in asset.ports),
        certificates=tuple(_certificate_to_dto(c) for c in asset.certificates),
        dns_records=tuple(_dns_record_to_dto(r) for r in asset.dns_records),
        fingerprints=tuple(_fingerprint_to_dto(f) for f in asset.fingerprints),
    )


class AssetApplicationService:
    def __init__(
        self,
        repository: IAssetRepository,
        unit_of_work: IUnitOfWork,
    ) -> None:
        self._repository = repository
        self._uow = unit_of_work

    # -- registration ----------------------------------------------------

    async def register_asset(self, cmd: RegisterAssetCommand) -> AssetDTO:
        validate_asset_identifier_present(cmd.domain_name, cmd.subdomain, cmd.ip_address)
        now = datetime.now(UTC)
        asset = AssetFactory.discover(
            tenant_id=cmd.tenant_id,
            asset_type=cmd.asset_type,
            now=now,
            domain_name=cmd.domain_name,
            subdomain=cmd.subdomain,
            ip_address=cmd.ip_address,
            discovery_source=cmd.discovery_source or DiscoverySource.MANUAL_ENTRY,
            asset_id=cmd.asset_id,
        )
        async with self._uow:
            await self._repository.save(asset)
            await self._uow.commit()
        return asset_to_dto(asset)

    # -- ports -------------------------------------------------------------

    async def record_open_port(self, cmd: RecordOpenPortCommand) -> AssetDTO:
        asset = await self._require_asset(cmd.tenant_id, cmd.asset_id)
        now = datetime.now(UTC)
        port = OpenPort(
            port_id=cmd.port_id or PortId.generate(),
            port_number=cmd.port_number,
            protocol=cmd.protocol,
            state=PortState.OPEN,
            detected_at=now,
            service=cmd.service,
        )
        asset.add_port(cmd.tenant_id, port, now)
        async with self._uow:
            await self._repository.save(asset)
            await self._uow.commit()
        return asset_to_dto(asset)

    async def close_port(self, cmd: ClosePortCommand) -> AssetDTO:
        asset = await self._require_asset(cmd.tenant_id, cmd.asset_id)
        asset.close_port(cmd.tenant_id, cmd.port_id, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(asset)
            await self._uow.commit()
        return asset_to_dto(asset)

    # -- certificates --------------------------------------------------------

    async def attach_certificate(self, cmd: AttachCertificateCommand) -> AssetDTO:
        asset = await self._require_asset(cmd.tenant_id, cmd.asset_id)
        certificate = Certificate(
            certificate_id=cmd.certificate_id or CertificateId.generate(),
            common_name=cmd.common_name,
            issuer=cmd.issuer,
            serial_number=cmd.serial_number,
            not_before=cmd.not_before,
            not_after=cmd.not_after,
            status=cmd.status,
        )
        asset.add_certificate(cmd.tenant_id, certificate, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(asset)
            await self._uow.commit()
        return asset_to_dto(asset)

    async def revoke_certificate(self, cmd: RevokeCertificateCommand) -> AssetDTO:
        asset = await self._require_asset(cmd.tenant_id, cmd.asset_id)
        asset.revoke_certificate(cmd.tenant_id, cmd.certificate_id, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(asset)
            await self._uow.commit()
        return asset_to_dto(asset)

    # -- dns records -----------------------------------------------------

    async def add_dns_record(self, cmd: AddDnsRecordCommand) -> AssetDTO:
        asset = await self._require_asset(cmd.tenant_id, cmd.asset_id)
        now = datetime.now(UTC)
        record = DnsRecordEntry(
            record_id=cmd.record_id or DnsRecordId.generate(),
            record_type=cmd.record_type,
            name=cmd.name,
            value=cmd.value,
            ttl_seconds=cmd.ttl_seconds,
            detected_at=now,
        )
        asset.add_dns_record(cmd.tenant_id, record, now)
        async with self._uow:
            await self._repository.save(asset)
            await self._uow.commit()
        return asset_to_dto(asset)

    async def remove_dns_record(self, cmd: RemoveDnsRecordCommand) -> AssetDTO:
        asset = await self._require_asset(cmd.tenant_id, cmd.asset_id)
        asset.remove_dns_record(cmd.tenant_id, cmd.record_id, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(asset)
            await self._uow.commit()
        return asset_to_dto(asset)

    # -- fingerprints, classification, criticality, ownership ----------------

    async def add_technology_fingerprint(self, cmd: AddTechnologyFingerprintCommand) -> AssetDTO:
        asset = await self._require_asset(cmd.tenant_id, cmd.asset_id)
        fingerprint = TechnologyFingerprint(
            name=cmd.name, version=cmd.version, confidence=cmd.confidence
        )
        asset.add_technology_fingerprint(cmd.tenant_id, fingerprint, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(asset)
            await self._uow.commit()
        return asset_to_dto(asset)

    async def evaluate_exposure(self, cmd: EvaluateExposureCommand) -> AssetDTO:
        asset = await self._require_asset(cmd.tenant_id, cmd.asset_id)
        new_state = ExposureEvaluationService.evaluate(asset)
        asset.update_exposure_state(cmd.tenant_id, new_state, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(asset)
            await self._uow.commit()
        return asset_to_dto(asset)

    async def recompute_criticality_score(
        self, cmd: RecomputeCriticalityScoreCommand
    ) -> CriticalityScoreDTO:
        """A pure derived-value computation: `Asset` has no persisted
        numeric-score field, so nothing on the aggregate changes and
        nothing is (re)saved — mirrors `CriticalityScoringService`'s own
        "orchestrates the policy, never mutates" contract."""
        asset = await self._require_asset(cmd.tenant_id, cmd.asset_id)
        now = datetime.now(UTC)
        score = CriticalityScoringService.score(asset, now)
        return CriticalityScoreDTO(
            asset_id=str(asset.asset_id),
            tenant_id=str(asset.tenant_id),
            score=score.value,
            computed_at=now,
        )

    async def set_criticality(self, cmd: SetCriticalityCommand) -> AssetDTO:
        asset = await self._require_asset(cmd.tenant_id, cmd.asset_id)
        asset.set_criticality(cmd.tenant_id, cmd.criticality, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(asset)
            await self._uow.commit()
        return asset_to_dto(asset)

    async def reclassify(self, cmd: ReclassifyAssetCommand) -> AssetDTO:
        asset = await self._require_asset(cmd.tenant_id, cmd.asset_id)
        asset.reclassify(cmd.tenant_id, cmd.classification, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(asset)
            await self._uow.commit()
        return asset_to_dto(asset)

    async def update_ownership(self, cmd: UpdateOwnershipCommand) -> AssetDTO:
        asset = await self._require_asset(cmd.tenant_id, cmd.asset_id)
        ownership = AssetOwnership(owning_team=cmd.owning_team, contact=cmd.contact)
        asset.assign_ownership(cmd.tenant_id, ownership, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(asset)
            await self._uow.commit()
        return asset_to_dto(asset)

    # -- lifecycle -----------------------------------------------------

    async def transition_lifecycle(self, cmd: TransitionAssetLifecycleCommand) -> AssetDTO:
        asset = await self._require_asset(cmd.tenant_id, cmd.asset_id)
        asset.transition_lifecycle(cmd.tenant_id, cmd.new_state, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(asset)
            await self._uow.commit()
        return asset_to_dto(asset)

    async def decommission(self, cmd: DecommissionAssetCommand) -> AssetDTO:
        asset = await self._require_asset(cmd.tenant_id, cmd.asset_id)
        asset.decommission(cmd.tenant_id, datetime.now(UTC))
        async with self._uow:
            await self._repository.save(asset)
            await self._uow.commit()
        return asset_to_dto(asset)

    # -- helpers -----------------------------------------------------------

    async def _require_asset(self, tenant_id: TenantId, asset_id: AssetId) -> Asset:
        asset = await self._repository.get(tenant_id, asset_id)
        if asset is None:
            raise AssetNotFoundError(asset_id)
        if asset.tenant_id != tenant_id:
            raise AssetTenantIsolationViolationError(tenant_id, asset.tenant_id)
        return asset
