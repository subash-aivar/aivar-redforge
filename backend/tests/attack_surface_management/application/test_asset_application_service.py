from __future__ import annotations

import pytest

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
from attack_surface_management.application.exceptions import (
    AssetNotFoundError,
    EmptyAssetIdentifierInputError,
)
from attack_surface_management.application.services.asset_application_service import (
    AssetApplicationService,
)
from attack_surface_management.domain.value_objects.enums import (
    AssetClassification,
    AssetLifecycleState,
    AssetType,
    CertificateStatus,
    Criticality,
    DnsRecordType,
    ExposureState,
    PortProtocol,
)
from attack_surface_management.domain.value_objects.identifiers import AssetId


@pytest.fixture
def service(asset_repository, unit_of_work) -> AssetApplicationService:
    return AssetApplicationService(asset_repository, unit_of_work)


async def _register(service, tenant_id, domain_name, asset_type=AssetType.INTERNET_FACING):
    return await service.register_asset(
        RegisterAssetCommand(tenant_id=tenant_id, asset_type=asset_type, domain_name=domain_name)
    )


class TestRegisterAsset:
    async def test_registers_and_persists(self, service, tenant_id, domain_name, unit_of_work):
        dto = await _register(service, tenant_id, domain_name)
        assert dto.tenant_id == str(tenant_id)
        assert dto.asset_type == AssetType.INTERNET_FACING.value
        assert dto.domain_name == "example.com"
        assert dto.lifecycle_state == AssetLifecycleState.DISCOVERED.value
        assert unit_of_work.committed == 1

    async def test_rejects_missing_identifier(self, service, tenant_id):
        with pytest.raises(EmptyAssetIdentifierInputError):
            await service.register_asset(
                RegisterAssetCommand(tenant_id=tenant_id, asset_type=AssetType.INTERNAL)
            )


class TestPorts:
    async def test_record_and_close_port(self, service, tenant_id, domain_name):
        asset = await _register(service, tenant_id, domain_name)
        asset_id = AssetId(__import__("uuid").UUID(asset.asset_id))
        dto = await service.record_open_port(
            RecordOpenPortCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                port_number=443,
                protocol=PortProtocol.TCP,
            )
        )
        assert len(dto.ports) == 1
        assert dto.ports[0].port_number == 443
        assert dto.ports[0].state == "open"

        port_id_str = dto.ports[0].port_id
        from attack_surface_management.domain.value_objects.identifiers import PortId

        closed = await service.close_port(
            ClosePortCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                port_id=PortId(__import__("uuid").UUID(port_id_str)),
            )
        )
        assert closed.ports[0].state == "closed"


class TestCertificates:
    async def test_attach_and_revoke_certificate(self, service, tenant_id, domain_name, now):
        asset = await _register(service, tenant_id, domain_name)
        asset_id = AssetId(__import__("uuid").UUID(asset.asset_id))
        from datetime import timedelta

        dto = await service.attach_certificate(
            AttachCertificateCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                common_name="example.com",
                issuer="Let's Encrypt",
                serial_number="abc123",
                not_before=now - timedelta(days=1),
                not_after=now + timedelta(days=89),
                status=CertificateStatus.VALID,
            )
        )
        assert len(dto.certificates) == 1
        cert_id_str = dto.certificates[0].certificate_id

        from attack_surface_management.domain.value_objects.identifiers import CertificateId

        revoked = await service.revoke_certificate(
            RevokeCertificateCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                certificate_id=CertificateId(__import__("uuid").UUID(cert_id_str)),
            )
        )
        assert revoked.certificates[0].status == "revoked"


class TestDnsRecords:
    async def test_add_and_remove_dns_record(self, service, tenant_id, domain_name):
        asset = await _register(service, tenant_id, domain_name)
        asset_id = AssetId(__import__("uuid").UUID(asset.asset_id))
        dto = await service.add_dns_record(
            AddDnsRecordCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                record_type=DnsRecordType.A,
                name="example.com",
                value="93.184.216.34",
                ttl_seconds=300,
            )
        )
        assert len(dto.dns_records) == 1
        record_id_str = dto.dns_records[0].record_id

        from attack_surface_management.domain.value_objects.identifiers import DnsRecordId

        removed = await service.remove_dns_record(
            RemoveDnsRecordCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                record_id=DnsRecordId(__import__("uuid").UUID(record_id_str)),
            )
        )
        assert len(removed.dns_records) == 0


class TestFingerprintsExposureAndCriticality:
    async def test_add_technology_fingerprint(self, service, tenant_id, domain_name):
        asset = await _register(service, tenant_id, domain_name)
        asset_id = AssetId(__import__("uuid").UUID(asset.asset_id))
        dto = await service.add_technology_fingerprint(
            AddTechnologyFingerprintCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                name="nginx",
                version="1.24.0",
                confidence=0.9,
            )
        )
        assert len(dto.fingerprints) == 1
        assert dto.fingerprints[0].name == "nginx"

    async def test_evaluate_exposure_reclassifies_after_high_risk_port(
        self, service, tenant_id, domain_name
    ):
        asset = await _register(service, tenant_id, domain_name)
        asset_id = AssetId(__import__("uuid").UUID(asset.asset_id))
        await service.record_open_port(
            RecordOpenPortCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                port_number=3389,
                protocol=PortProtocol.TCP,
            )
        )
        dto = await service.evaluate_exposure(
            EvaluateExposureCommand(tenant_id=tenant_id, asset_id=asset_id)
        )
        assert dto.exposure_state == ExposureState.EXPOSED_HIGH_RISK.value

    async def test_recompute_criticality_score_does_not_mutate_or_save(
        self, service, tenant_id, domain_name, unit_of_work
    ):
        asset = await _register(service, tenant_id, domain_name)
        asset_id = AssetId(__import__("uuid").UUID(asset.asset_id))
        committed_before = unit_of_work.committed
        score_dto = await service.recompute_criticality_score(
            RecomputeCriticalityScoreCommand(tenant_id=tenant_id, asset_id=asset_id)
        )
        assert 0 <= score_dto.score <= 100
        assert unit_of_work.committed == committed_before

    async def test_set_criticality(self, service, tenant_id, domain_name):
        asset = await _register(service, tenant_id, domain_name)
        asset_id = AssetId(__import__("uuid").UUID(asset.asset_id))
        dto = await service.set_criticality(
            SetCriticalityCommand(
                tenant_id=tenant_id, asset_id=asset_id, criticality=Criticality.CRITICAL
            )
        )
        assert dto.criticality == Criticality.CRITICAL.value

    async def test_reclassify(self, service, tenant_id, domain_name):
        asset = await _register(service, tenant_id, domain_name)
        asset_id = AssetId(__import__("uuid").UUID(asset.asset_id))
        dto = await service.reclassify(
            ReclassifyAssetCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                classification=AssetClassification.PRODUCTION,
            )
        )
        assert dto.classification == AssetClassification.PRODUCTION.value


class TestOwnershipAndLifecycle:
    async def test_update_ownership(self, service, tenant_id, domain_name):
        asset = await _register(service, tenant_id, domain_name)
        asset_id = AssetId(__import__("uuid").UUID(asset.asset_id))
        dto = await service.update_ownership(
            UpdateOwnershipCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                owning_team="platform-security",
                contact="secteam@example.com",
            )
        )
        assert dto.ownership is not None
        assert dto.ownership.owning_team == "platform-security"

    async def test_transition_lifecycle_and_decommission(self, service, tenant_id, domain_name):
        asset = await _register(service, tenant_id, domain_name)
        asset_id = AssetId(__import__("uuid").UUID(asset.asset_id))
        validated = await service.transition_lifecycle(
            TransitionAssetLifecycleCommand(
                tenant_id=tenant_id,
                asset_id=asset_id,
                new_state=AssetLifecycleState.VALIDATED,
            )
        )
        assert validated.lifecycle_state == AssetLifecycleState.VALIDATED.value
        active = await service.transition_lifecycle(
            TransitionAssetLifecycleCommand(
                tenant_id=tenant_id, asset_id=asset_id, new_state=AssetLifecycleState.ACTIVE
            )
        )
        assert active.lifecycle_state == AssetLifecycleState.ACTIVE.value
        decommissioned = await service.decommission(
            DecommissionAssetCommand(tenant_id=tenant_id, asset_id=asset_id)
        )
        assert decommissioned.lifecycle_state == AssetLifecycleState.DECOMMISSIONED.value


class TestNotFoundAndTenantIsolation:
    async def test_not_found_raises(self, service, tenant_id):
        with pytest.raises(AssetNotFoundError):
            await service.decommission(
                DecommissionAssetCommand(tenant_id=tenant_id, asset_id=AssetId.generate())
            )

    async def test_cross_tenant_get_returns_none_at_repository_layer(
        self, service, tenant_id, other_tenant_id, domain_name
    ):
        asset = await _register(service, tenant_id, domain_name)
        asset_id = AssetId(__import__("uuid").UUID(asset.asset_id))
        with pytest.raises(AssetNotFoundError):
            await service.decommission(
                DecommissionAssetCommand(tenant_id=other_tenant_id, asset_id=asset_id)
            )
