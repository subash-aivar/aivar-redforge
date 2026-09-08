from __future__ import annotations

from infrastructure_intel.domain.factories.infrastructure_factory import (
    InfrastructureFactory,
)
from infrastructure_intel.domain.specifications.infrastructure_specifications import (
    ActiveInfrastructureSpecification,
    CloudHostedInfrastructureSpecification,
    DeprecatedOrRevokedInfrastructureSpecification,
    IsGlobalInfrastructureSpecification,
    IsTenantInfrastructureSpecification,
    SupersededInfrastructureSpecification,
)
from infrastructure_intel.domain.value_objects.enums import (
    CloudProvider,
    InfrastructureType,
)
from infrastructure_intel.domain.value_objects.hosting import CloudProviderRef
from infrastructure_intel.domain.value_objects.identifiers import InfrastructureId

T = InfrastructureType


def _observe(now, tenant_id=None, identifier="AS15169"):
    return InfrastructureFactory().observe(
        tenant_id=tenant_id,
        infrastructure_type=T.ASN,
        normalized_identifier=identifier,
        now=now,
    )


def test_active_specification_matches_a_freshly_observed_record(now) -> None:
    record = _observe(now)
    assert ActiveInfrastructureSpecification().is_satisfied_by(record)
    assert not DeprecatedOrRevokedInfrastructureSpecification().is_satisfied_by(record)
    assert not SupersededInfrastructureSpecification().is_satisfied_by(record)


def test_deprecated_or_revoked_specification(now, evidence) -> None:
    deprecated = _observe(now, identifier="AS15169")
    deprecated.deprecate(None, evidence, now)
    revoked = _observe(now, identifier="AS64512")
    revoked.revoke(None, evidence, now)

    spec = DeprecatedOrRevokedInfrastructureSpecification()
    assert spec.is_satisfied_by(deprecated)
    assert spec.is_satisfied_by(revoked)
    assert not ActiveInfrastructureSpecification().is_satisfied_by(deprecated)
    assert not ActiveInfrastructureSpecification().is_satisfied_by(revoked)


def test_superseded_specification(now, evidence) -> None:
    record = _observe(now)
    record.supersede(None, InfrastructureId.generate(), evidence, now)
    assert SupersededInfrastructureSpecification().is_satisfied_by(record)
    assert not DeprecatedOrRevokedInfrastructureSpecification().is_satisfied_by(record)


def test_scope_specifications(now, tenant_id) -> None:
    global_record = _observe(now, tenant_id=None, identifier="AS15169")
    tenant_record = _observe(now, tenant_id=tenant_id, identifier="AS64512")

    assert IsGlobalInfrastructureSpecification().is_satisfied_by(global_record)
    assert not IsGlobalInfrastructureSpecification().is_satisfied_by(tenant_record)
    assert IsTenantInfrastructureSpecification().is_satisfied_by(tenant_record)
    assert not IsTenantInfrastructureSpecification().is_satisfied_by(global_record)


def test_cloud_hosted_specification(now) -> None:
    on_prem = _observe(now)
    cloud = _observe(now, identifier="AS64512")
    cloud.set_cloud_provider(None, CloudProviderRef(provider=CloudProvider.AWS), now)

    spec = CloudHostedInfrastructureSpecification()
    assert spec.is_satisfied_by(cloud)
    assert not spec.is_satisfied_by(on_prem)


def test_reactivation_restores_the_active_specification(now, evidence) -> None:
    record = _observe(now)
    record.deprecate(None, evidence, now)
    assert not ActiveInfrastructureSpecification().is_satisfied_by(record)
    record.reactivate(None, evidence, now)
    assert ActiveInfrastructureSpecification().is_satisfied_by(record)
