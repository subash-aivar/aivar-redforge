from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from attack_surface_management.domain.entities.certificate import Certificate
from attack_surface_management.domain.entities.dns_record import DnsRecordEntry
from attack_surface_management.domain.entities.open_port import OpenPort
from attack_surface_management.domain.exceptions.domain_exceptions import (
    InvalidCertificateWindowError,
    InvalidDnsRecordError,
    InvalidPortNumberError,
)
from attack_surface_management.domain.value_objects.enums import (
    CertificateStatus,
    DnsRecordType,
    PortProtocol,
    PortState,
)
from attack_surface_management.domain.value_objects.identifiers import (
    CertificateId,
    DnsRecordId,
    PortId,
)
from attack_surface_management.domain.value_objects.service_banner import ServiceBanner

NOW = datetime(2026, 1, 1, tzinfo=UTC)


# -- OpenPort ------------------------------------------------------------


def test_open_port_rejects_invalid_port_number() -> None:
    with pytest.raises(InvalidPortNumberError):
        OpenPort(
            port_id=PortId.generate(),
            port_number=70000,
            protocol=PortProtocol.TCP,
            state=PortState.OPEN,
            detected_at=NOW,
        )


def test_open_port_is_high_risk_by_conventional_port() -> None:
    port = OpenPort(
        port_id=PortId.generate(),
        port_number=3389,
        protocol=PortProtocol.TCP,
        state=PortState.OPEN,
        detected_at=NOW,
    )
    assert port.is_high_risk is True


def test_open_port_is_high_risk_by_service_on_nonstandard_port() -> None:
    port = OpenPort(
        port_id=PortId.generate(),
        port_number=8023,
        protocol=PortProtocol.TCP,
        state=PortState.OPEN,
        detected_at=NOW,
        service=ServiceBanner(name="telnet"),
    )
    assert port.is_high_risk is True


def test_open_port_close_preserves_identity() -> None:
    port_id = PortId.generate()
    port = OpenPort(
        port_id=port_id,
        port_number=443,
        protocol=PortProtocol.TCP,
        state=PortState.OPEN,
        detected_at=NOW,
    )
    closed = port.close(NOW + timedelta(hours=1))
    assert closed.port_id == port_id
    assert closed.state == PortState.CLOSED
    assert closed is not port


def test_open_port_with_service_preserves_identity() -> None:
    port_id = PortId.generate()
    port = OpenPort(
        port_id=port_id,
        port_number=443,
        protocol=PortProtocol.TCP,
        state=PortState.OPEN,
        detected_at=NOW,
    )
    fingerprinted = port.with_service(ServiceBanner(name="https"), NOW)
    assert fingerprinted.port_id == port_id
    assert fingerprinted.service is not None
    assert fingerprinted.service.name == "https"


# -- Certificate -----------------------------------------------------------


def _certificate(status: CertificateStatus = CertificateStatus.VALID) -> Certificate:
    return Certificate(
        certificate_id=CertificateId.generate(),
        common_name="example.com",
        issuer="Let's Encrypt",
        serial_number="abc123",
        not_before=NOW,
        not_after=NOW + timedelta(days=90),
        status=status,
    )


def test_certificate_rejects_inverted_validity_window() -> None:
    with pytest.raises(InvalidCertificateWindowError):
        Certificate(
            certificate_id=CertificateId.generate(),
            common_name="example.com",
            issuer="Let's Encrypt",
            serial_number="abc123",
            not_before=NOW,
            not_after=NOW - timedelta(days=1),
            status=CertificateStatus.VALID,
        )


def test_certificate_rejects_empty_common_name() -> None:
    with pytest.raises(InvalidCertificateWindowError):
        Certificate(
            certificate_id=CertificateId.generate(),
            common_name="  ",
            issuer="Let's Encrypt",
            serial_number="abc123",
            not_before=NOW,
            not_after=NOW + timedelta(days=1),
            status=CertificateStatus.VALID,
        )


def test_certificate_is_expired() -> None:
    cert = _certificate()
    assert cert.is_expired(NOW + timedelta(days=91)) is True
    assert cert.is_expired(NOW + timedelta(days=1)) is False


def test_certificate_expires_within_window() -> None:
    cert = _certificate()
    assert cert.expires_within(NOW + timedelta(days=80), window_days=30) is True
    assert cert.expires_within(NOW, window_days=30) is False


def test_certificate_revoke_preserves_identity() -> None:
    cert = _certificate()
    revoked = cert.revoke()
    assert revoked.certificate_id == cert.certificate_id
    assert revoked.status == CertificateStatus.REVOKED


def test_certificate_mark_expired_preserves_identity() -> None:
    cert = _certificate()
    expired = cert.mark_expired()
    assert expired.certificate_id == cert.certificate_id
    assert expired.status == CertificateStatus.EXPIRED


# -- DnsRecordEntry --------------------------------------------------------


def test_dns_record_rejects_empty_name_or_value() -> None:
    with pytest.raises(InvalidDnsRecordError):
        DnsRecordEntry(
            record_id=DnsRecordId.generate(),
            record_type=DnsRecordType.A,
            name="",
            value="1.2.3.4",
            ttl_seconds=300,
            detected_at=NOW,
        )
    with pytest.raises(InvalidDnsRecordError):
        DnsRecordEntry(
            record_id=DnsRecordId.generate(),
            record_type=DnsRecordType.A,
            name="example.com",
            value="",
            ttl_seconds=300,
            detected_at=NOW,
        )


def test_dns_record_rejects_negative_ttl() -> None:
    with pytest.raises(InvalidDnsRecordError):
        DnsRecordEntry(
            record_id=DnsRecordId.generate(),
            record_type=DnsRecordType.A,
            name="example.com",
            value="1.2.3.4",
            ttl_seconds=-1,
            detected_at=NOW,
        )
