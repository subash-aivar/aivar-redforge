from __future__ import annotations

from datetime import UTC, datetime, timedelta

from attack_surface_management.domain.entities.certificate import Certificate
from attack_surface_management.domain.entities.open_port import OpenPort
from attack_surface_management.domain.factories.asset_factory import AssetFactory
from attack_surface_management.domain.services.criticality_scoring_service import (
    CriticalityScoringService,
)
from attack_surface_management.domain.services.exposure_evaluation_service import (
    ExposureEvaluationService,
)
from attack_surface_management.domain.value_objects.domain_name import DomainName
from attack_surface_management.domain.value_objects.enums import (
    AssetType,
    CertificateStatus,
    Criticality,
    ExposureState,
    PortProtocol,
    PortState,
)
from attack_surface_management.domain.value_objects.identifiers import (
    CertificateId,
    PortId,
    TenantId,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _asset(tenant_id: TenantId):
    return AssetFactory.discover(
        tenant_id=tenant_id,
        asset_type=AssetType.INTERNET_FACING,
        now=NOW,
        domain_name=DomainName("example.com"),
    )


def test_exposure_evaluation_service_matches_policy(tenant_id: TenantId) -> None:
    asset = _asset(tenant_id)
    assert ExposureEvaluationService.evaluate(asset) == ExposureState.INTERNET_FACING
    assert ExposureEvaluationService.needs_reclassification(asset) is True

    asset.update_exposure_state(tenant_id, ExposureState.INTERNET_FACING, NOW)
    assert ExposureEvaluationService.needs_reclassification(asset) is False


def test_exposure_evaluation_service_detects_high_risk_port(tenant_id: TenantId) -> None:
    asset = _asset(tenant_id)
    asset.add_port(
        tenant_id,
        OpenPort(
            port_id=PortId.generate(),
            port_number=3389,
            protocol=PortProtocol.TCP,
            state=PortState.OPEN,
            detected_at=NOW,
        ),
        NOW,
    )
    assert ExposureEvaluationService.evaluate(asset) == ExposureState.EXPOSED_HIGH_RISK


def test_criticality_scoring_service_uses_base_policy(tenant_id: TenantId) -> None:
    asset = _asset(tenant_id)
    asset.set_criticality(tenant_id, Criticality.HIGH, NOW)
    asset.update_exposure_state(tenant_id, ExposureState.INTERNET_FACING, NOW)
    score = CriticalityScoringService.score(asset, NOW)
    assert score.value == 70  # 60 base + 10 exposure bonus


def test_criticality_scoring_service_applies_certificate_expiry_penalty(
    tenant_id: TenantId,
) -> None:
    asset = _asset(tenant_id)
    asset.set_criticality(tenant_id, Criticality.HIGH, NOW)
    asset.update_exposure_state(tenant_id, ExposureState.INTERNET_FACING, NOW)
    expiring_cert = Certificate(
        certificate_id=CertificateId.generate(),
        common_name="example.com",
        issuer="Let's Encrypt",
        serial_number="abc123",
        not_before=NOW - timedelta(days=60),
        not_after=NOW + timedelta(days=10),
        status=CertificateStatus.VALID,
    )
    asset.add_certificate(tenant_id, expiring_cert, NOW)
    score = CriticalityScoringService.score(asset, NOW)
    assert score.value == 85  # 60 base + 10 exposure + 15 expiry penalty
