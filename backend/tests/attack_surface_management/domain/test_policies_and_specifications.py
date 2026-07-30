from __future__ import annotations

from datetime import UTC, datetime, timedelta

from attack_surface_management.domain.entities.certificate import Certificate
from attack_surface_management.domain.entities.open_port import OpenPort
from attack_surface_management.domain.factories.asset_factory import AssetFactory
from attack_surface_management.domain.policies.criticality_scoring_policy import (
    CriticalityScoringPolicy,
)
from attack_surface_management.domain.policies.exposure_classification_policy import (
    ExposureClassificationPolicy,
)
from attack_surface_management.domain.policies.lifecycle_transition_policy import (
    AssetLifecycleTransitionPolicy,
    NetworkRangeLifecycleTransitionPolicy,
)
from attack_surface_management.domain.specifications.asset_specifications import (
    HasExpiredCertificateSpecification,
    HasOpenHighRiskPortSpecification,
    IsExposedHighRiskSpecification,
    IsStaleAssetSpecification,
    IsUnownedSpecification,
)
from attack_surface_management.domain.value_objects.criticality_score import CriticalityScore
from attack_surface_management.domain.value_objects.domain_name import DomainName
from attack_surface_management.domain.value_objects.enums import (
    AssetLifecycleState,
    AssetType,
    CertificateStatus,
    Criticality,
    ExposureState,
    NetworkRangeLifecycleState,
    PortProtocol,
    PortState,
)
from attack_surface_management.domain.value_objects.identifiers import (
    CertificateId,
    PortId,
    TenantId,
)

NOW = datetime(2026, 1, 1, tzinfo=UTC)


def _asset(tenant_id: TenantId, asset_type: AssetType = AssetType.INTERNET_FACING):
    return AssetFactory.discover(
        tenant_id=tenant_id, asset_type=asset_type, now=NOW, domain_name=DomainName("example.com")
    )


def _port(number: int, state: PortState = PortState.OPEN) -> OpenPort:
    return OpenPort(
        port_id=PortId.generate(),
        port_number=number,
        protocol=PortProtocol.TCP,
        state=state,
        detected_at=NOW,
    )


# -- ExposureClassificationPolicy -----------------------------------------


def test_internal_asset_is_never_exposed() -> None:
    assert (
        ExposureClassificationPolicy.classify(AssetType.INTERNAL, (_port(443),))
        == ExposureState.NOT_EXPOSED
    )


def test_internet_facing_with_no_high_risk_port_is_internet_facing() -> None:
    assert (
        ExposureClassificationPolicy.classify(AssetType.INTERNET_FACING, (_port(443),))
        == ExposureState.INTERNET_FACING
    )


def test_internet_facing_with_high_risk_port_is_high_risk() -> None:
    assert (
        ExposureClassificationPolicy.classify(AssetType.INTERNET_FACING, (_port(3389),))
        == ExposureState.EXPOSED_HIGH_RISK
    )


def test_closed_high_risk_port_does_not_count() -> None:
    assert (
        ExposureClassificationPolicy.classify(
            AssetType.INTERNET_FACING, (_port(3389, PortState.CLOSED),)
        )
        == ExposureState.INTERNET_FACING
    )


# -- CriticalityScoringPolicy ----------------------------------------------


def test_criticality_scoring_combines_tier_and_exposure() -> None:
    score = CriticalityScoringPolicy.score(Criticality.CRITICAL, ExposureState.EXPOSED_HIGH_RISK)
    assert score == CriticalityScore(100)

    score = CriticalityScoringPolicy.score(Criticality.LOW, ExposureState.NOT_EXPOSED)
    assert score == CriticalityScore(20)


def test_criticality_scoring_caps_at_100() -> None:
    score = CriticalityScoringPolicy.score(Criticality.CRITICAL, ExposureState.EXPOSED_HIGH_RISK)
    assert score.value <= 100


# -- lifecycle transition policies -----------------------------------------


def test_asset_lifecycle_policy_allows_expected_path() -> None:
    assert AssetLifecycleTransitionPolicy.is_allowed(
        AssetLifecycleState.DISCOVERED, AssetLifecycleState.VALIDATED
    )
    assert AssetLifecycleTransitionPolicy.is_allowed(
        AssetLifecycleState.ACTIVE, AssetLifecycleState.DECOMMISSIONED
    )
    assert not AssetLifecycleTransitionPolicy.is_allowed(
        AssetLifecycleState.DECOMMISSIONED, AssetLifecycleState.ACTIVE
    )


def test_network_range_lifecycle_policy_allows_expected_path() -> None:
    assert NetworkRangeLifecycleTransitionPolicy.is_allowed(
        NetworkRangeLifecycleState.DISCOVERED, NetworkRangeLifecycleState.ACTIVE
    )
    assert not NetworkRangeLifecycleTransitionPolicy.is_allowed(
        NetworkRangeLifecycleState.RETIRED, NetworkRangeLifecycleState.ACTIVE
    )


# -- specifications ---------------------------------------------------------


def test_is_exposed_high_risk_specification(tenant_id: TenantId) -> None:
    asset = _asset(tenant_id)
    assert not IsExposedHighRiskSpecification().is_satisfied_by(asset)
    asset.update_exposure_state(tenant_id, ExposureState.EXPOSED_HIGH_RISK, NOW)
    assert IsExposedHighRiskSpecification().is_satisfied_by(asset)


def test_is_stale_asset_specification(tenant_id: TenantId) -> None:
    asset = _asset(tenant_id)
    spec = IsStaleAssetSpecification(max_age=timedelta(days=30))
    assert not spec.is_satisfied_by(asset, NOW)
    assert spec.is_satisfied_by(asset, NOW + timedelta(days=31))


def test_has_open_high_risk_port_specification(tenant_id: TenantId) -> None:
    asset = _asset(tenant_id)
    assert not HasOpenHighRiskPortSpecification().is_satisfied_by(asset)
    asset.add_port(tenant_id, _port(3389), NOW)
    assert HasOpenHighRiskPortSpecification().is_satisfied_by(asset)


def test_has_expired_certificate_specification(tenant_id: TenantId) -> None:
    asset = _asset(tenant_id)
    cert = Certificate(
        certificate_id=CertificateId.generate(),
        common_name="example.com",
        issuer="Let's Encrypt",
        serial_number="abc123",
        not_before=NOW - timedelta(days=100),
        not_after=NOW - timedelta(days=1),
        status=CertificateStatus.EXPIRED,
    )
    asset.add_certificate(tenant_id, cert, NOW)
    assert HasExpiredCertificateSpecification().is_satisfied_by(asset, NOW)


def test_is_unowned_specification(tenant_id: TenantId) -> None:
    from attack_surface_management.domain.value_objects.asset_ownership import AssetOwnership

    asset = _asset(tenant_id)
    assert IsUnownedSpecification().is_satisfied_by(asset)
    asset.assign_ownership(tenant_id, AssetOwnership(owning_team="sec"), NOW)
    assert not IsUnownedSpecification().is_satisfied_by(asset)
