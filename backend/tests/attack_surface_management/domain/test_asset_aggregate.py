from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from attack_surface_management.domain.entities.certificate import Certificate
from attack_surface_management.domain.entities.dns_record import DnsRecordEntry
from attack_surface_management.domain.entities.open_port import OpenPort
from attack_surface_management.domain.events.asset_events import (
    AssetCertificateAdded,
    AssetCertificateRevoked,
    AssetCriticalityChanged,
    AssetDiscovered,
    AssetDnsRecordAdded,
    AssetDnsRecordRemoved,
    AssetExposureStateChanged,
    AssetLifecycleTransitioned,
    AssetOwnershipAssigned,
    AssetPortClosed,
    AssetPortDiscovered,
    AssetReclassified,
    AssetTechnologyFingerprintAdded,
)
from attack_surface_management.domain.exceptions.domain_exceptions import (
    CertificateNotFoundError,
    DnsRecordNotFoundError,
    DuplicatePortError,
    EmptyAssetIdentifierError,
    InvalidAssetLifecycleTransition,
    PortNotFoundError,
    TenantMismatch,
)
from attack_surface_management.domain.factories.asset_factory import AssetFactory
from attack_surface_management.domain.value_objects.asset_ownership import AssetOwnership
from attack_surface_management.domain.value_objects.domain_name import DomainName
from attack_surface_management.domain.value_objects.enums import (
    AssetClassification,
    AssetLifecycleState,
    AssetType,
    CertificateStatus,
    Criticality,
    DnsRecordType,
    ExposureState,
    PortProtocol,
    PortState,
)
from attack_surface_management.domain.value_objects.identifiers import (
    CertificateId,
    DnsRecordId,
    PortId,
    TenantId,
)
from attack_surface_management.domain.value_objects.technology_fingerprint import (
    TechnologyFingerprint,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _create(tenant_id: TenantId):
    return AssetFactory.discover(
        tenant_id=tenant_id,
        asset_type=AssetType.INTERNET_FACING,
        now=NOW,
        domain_name=DomainName("example.com"),
    )


def _port(number: int = 443, state: PortState = PortState.OPEN) -> OpenPort:
    return OpenPort(
        port_id=PortId.generate(),
        port_number=number,
        protocol=PortProtocol.TCP,
        state=state,
        detected_at=NOW,
    )


# -- construction ----------------------------------------------------


def test_asset_requires_at_least_one_identifier(tenant_id: TenantId) -> None:
    from attack_surface_management.domain.aggregates.asset import Asset
    from attack_surface_management.domain.value_objects.identifiers import AssetId

    with pytest.raises(EmptyAssetIdentifierError):
        Asset(
            asset_id=AssetId.generate(),
            tenant_id=tenant_id,
            asset_type=AssetType.INTERNAL,
            created_at=NOW,
        )


def test_factory_creates_asset_and_emits_discovered_event(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    assert asset.lifecycle_state == AssetLifecycleState.DISCOVERED
    assert asset.primary_identifier == "example.com"
    events = asset.pop_events()
    assert len(events) == 1
    assert isinstance(events[0], AssetDiscovered)
    assert events[0].primary_identifier == "example.com"


# -- ports -------------------------------------------------------------


def test_add_port_appends_and_emits_event(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    asset.pop_events()
    port = _port()
    asset.add_port(tenant_id, port, NOW)
    assert asset.ports == (port,)
    events = asset.pop_events()
    assert any(isinstance(e, AssetPortDiscovered) for e in events)


def test_add_duplicate_open_port_is_rejected(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    asset.add_port(tenant_id, _port(443), NOW)
    with pytest.raises(DuplicatePortError):
        asset.add_port(tenant_id, _port(443), NOW)


def test_close_port_preserves_other_ports_and_emits_event(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    port = _port(443)
    asset.add_port(tenant_id, port, NOW)
    other = _port(8443)
    asset.add_port(tenant_id, other, NOW)
    asset.pop_events()

    asset.close_port(tenant_id, port.port_id, NOW + timedelta(hours=1))
    closed = next(p for p in asset.ports if p.port_id == port.port_id)
    assert closed.state == PortState.CLOSED
    still_open = next(p for p in asset.ports if p.port_id == other.port_id)
    assert still_open.state == PortState.OPEN
    events = asset.pop_events()
    assert any(isinstance(e, AssetPortClosed) for e in events)


def test_close_unknown_port_raises(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    with pytest.raises(PortNotFoundError):
        asset.close_port(tenant_id, PortId.generate(), NOW)


# -- certificates -----------------------------------------------------


def _certificate() -> Certificate:
    return Certificate(
        certificate_id=CertificateId.generate(),
        common_name="example.com",
        issuer="Let's Encrypt",
        serial_number="abc123",
        not_before=NOW,
        not_after=NOW + timedelta(days=90),
        status=CertificateStatus.VALID,
    )


def test_add_certificate_emits_event(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    asset.pop_events()
    cert = _certificate()
    asset.add_certificate(tenant_id, cert, NOW)
    assert asset.certificates == (cert,)
    events = asset.pop_events()
    assert any(isinstance(e, AssetCertificateAdded) for e in events)


def test_revoke_certificate_preserves_identity_and_emits_event(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    cert = _certificate()
    asset.add_certificate(tenant_id, cert, NOW)
    asset.pop_events()
    asset.revoke_certificate(tenant_id, cert.certificate_id, NOW)
    revoked = asset.certificates[0]
    assert revoked.certificate_id == cert.certificate_id
    assert revoked.status == CertificateStatus.REVOKED
    events = asset.pop_events()
    assert any(isinstance(e, AssetCertificateRevoked) for e in events)


def test_revoke_unknown_certificate_raises(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    with pytest.raises(CertificateNotFoundError):
        asset.revoke_certificate(tenant_id, CertificateId.generate(), NOW)


# -- dns records -------------------------------------------------------


def _dns_record() -> DnsRecordEntry:
    return DnsRecordEntry(
        record_id=DnsRecordId.generate(),
        record_type=DnsRecordType.A,
        name="example.com",
        value="93.184.216.34",
        ttl_seconds=300,
        detected_at=NOW,
    )


def test_add_and_remove_dns_record(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    record = _dns_record()
    asset.add_dns_record(tenant_id, record, NOW)
    assert asset.dns_records == (record,)
    events = asset.pop_events()
    assert any(isinstance(e, AssetDnsRecordAdded) for e in events)

    asset.remove_dns_record(tenant_id, record.record_id, NOW)
    assert asset.dns_records == ()
    events = asset.pop_events()
    assert any(isinstance(e, AssetDnsRecordRemoved) for e in events)


def test_remove_unknown_dns_record_raises(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    with pytest.raises(DnsRecordNotFoundError):
        asset.remove_dns_record(tenant_id, DnsRecordId.generate(), NOW)


# -- fingerprints, classification, criticality, ownership -----------------


def test_add_technology_fingerprint(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    asset.pop_events()
    fp = TechnologyFingerprint(name="nginx", version="1.24.0", confidence=0.9)
    asset.add_technology_fingerprint(tenant_id, fp, NOW)
    assert asset.fingerprints == (fp,)
    events = asset.pop_events()
    assert any(isinstance(e, AssetTechnologyFingerprintAdded) for e in events)


def test_update_exposure_state_emits_event_only_on_change(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    asset.pop_events()
    asset.update_exposure_state(tenant_id, ExposureState.INTERNET_FACING, NOW)
    assert asset.exposure_state == ExposureState.INTERNET_FACING
    events = asset.pop_events()
    assert any(isinstance(e, AssetExposureStateChanged) for e in events)

    asset.update_exposure_state(tenant_id, ExposureState.INTERNET_FACING, NOW)
    assert asset.pop_events() == []


def test_set_criticality_emits_event(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    asset.pop_events()
    asset.set_criticality(tenant_id, Criticality.HIGH, NOW)
    events = asset.pop_events()
    assert any(isinstance(e, AssetCriticalityChanged) for e in events)


def test_reclassify_emits_event(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    asset.pop_events()
    asset.reclassify(tenant_id, AssetClassification.PRODUCTION, NOW)
    events = asset.pop_events()
    assert any(isinstance(e, AssetReclassified) for e in events)


def test_assign_ownership_emits_event(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    asset.pop_events()
    asset.assign_ownership(tenant_id, AssetOwnership(owning_team="platform-security"), NOW)
    assert asset.ownership is not None
    events = asset.pop_events()
    assert any(isinstance(e, AssetOwnershipAssigned) for e in events)


# -- lifecycle -----------------------------------------------------------


def test_lifecycle_happy_path(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    asset.pop_events()
    asset.transition_lifecycle(tenant_id, AssetLifecycleState.VALIDATED, NOW)
    asset.transition_lifecycle(tenant_id, AssetLifecycleState.ACTIVE, NOW)
    asset.decommission(tenant_id, NOW)
    assert asset.lifecycle_state == AssetLifecycleState.DECOMMISSIONED
    events = asset.pop_events()
    assert sum(isinstance(e, AssetLifecycleTransitioned) for e in events) == 3


def test_lifecycle_rejects_illegal_transition(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    with pytest.raises(InvalidAssetLifecycleTransition):
        asset.transition_lifecycle(tenant_id, AssetLifecycleState.ACTIVE, NOW)


def test_lifecycle_decommissioned_is_terminal(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    asset.transition_lifecycle(tenant_id, AssetLifecycleState.VALIDATED, NOW)
    asset.transition_lifecycle(tenant_id, AssetLifecycleState.ACTIVE, NOW)
    asset.decommission(tenant_id, NOW)
    with pytest.raises(InvalidAssetLifecycleTransition):
        asset.transition_lifecycle(tenant_id, AssetLifecycleState.ACTIVE, NOW)


# -- tenant isolation -----------------------------------------------------


def test_tenant_mismatch_raised_on_mutating_methods(tenant_id: TenantId) -> None:
    asset = _create(tenant_id)
    other = TenantId.generate()
    with pytest.raises(TenantMismatch):
        asset.add_port(other, _port(), NOW)
    with pytest.raises(TenantMismatch):
        asset.set_criticality(other, Criticality.HIGH, NOW)
    with pytest.raises(TenantMismatch):
        asset.transition_lifecycle(other, AssetLifecycleState.VALIDATED, NOW)
