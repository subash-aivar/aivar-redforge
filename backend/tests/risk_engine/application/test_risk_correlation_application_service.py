from __future__ import annotations

from datetime import timedelta
from uuid import UUID

import pytest

from risk_engine.application.commands.risk_correlation_commands import (
    EvaluateRiskAcceptanceExpiryCommand,
    EvaluateRiskEscalationCommand,
    FormRiskCorrelationSetsCommand,
)
from risk_engine.application.commands.risk_profile_commands import (
    AcceptEnterpriseRiskCommand,
    AcknowledgeEnterpriseRiskCommand,
    CreateEnterpriseRiskProfileCommand,
    MitigateEnterpriseRiskCommand,
    RecomputeEnterpriseRiskCommand,
    RiskDimensionSignal,
)
from risk_engine.application.exceptions import (
    EnterpriseRiskProfileNotFoundError,
    RiskProfileNotAcceptedError,
    RiskTenantIsolationViolationError,
)
from risk_engine.application.queries.risk_profile_queries import GetRiskTimelineQuery
from risk_engine.application.services.enterprise_risk_profile_service import (
    EnterpriseRiskProfileApplicationService,
)
from risk_engine.application.services.risk_correlation_application_service import (
    RiskCorrelationApplicationService,
)
from risk_engine.application.services.risk_timeline_service import (
    RiskTimelineApplicationService,
)
from risk_engine.domain.value_objects.enums import RiskDimension, RiskProfileStatus
from risk_engine.domain.value_objects.identifiers import RiskProfileId
from risk_engine.domain.value_objects.normalized_score import NormalizedRiskScore
from tests.risk_engine.application.conftest import make_signal_reference, make_weight_profile


@pytest.fixture
def profile_service(profile_repository, unit_of_work) -> EnterpriseRiskProfileApplicationService:
    return EnterpriseRiskProfileApplicationService(profile_repository, unit_of_work)


@pytest.fixture
def timeline_service(profile_repository) -> RiskTimelineApplicationService:
    return RiskTimelineApplicationService(profile_repository)


@pytest.fixture
def service(
    correlation_repository,
    profile_repository,
    unit_of_work,
    profile_service,
    timeline_service,
) -> RiskCorrelationApplicationService:
    return RiskCorrelationApplicationService(
        correlation_repository,
        profile_repository,
        unit_of_work,
        profile_service,
        timeline_service,
    )


async def _create_profile(profile_service, tenant_id, subject_reference="asset-123"):
    cmd = CreateEnterpriseRiskProfileCommand(
        tenant_id=tenant_id,
        subject_reference=subject_reference,
        dimension=RiskDimension.VULNERABILITY,
        signal_reference=make_signal_reference(tenant_id, subject_reference=subject_reference),
    )
    return await profile_service.create_profile(cmd)


# -- correlation orchestration ------------------------------------------------


async def test_form_correlation_sets_clusters_correlatable_signals(service, tenant_id, now):
    sig_a = make_signal_reference(
        tenant_id, subject_reference="asset-1", source_id="a", observed_at=now
    )
    sig_b = make_signal_reference(
        tenant_id,
        subject_reference="asset-1",
        source_id="b",
        observed_at=now + timedelta(minutes=5),
    )
    sig_c = make_signal_reference(
        tenant_id, subject_reference="asset-2", source_id="c", observed_at=now
    )
    cmd = FormRiskCorrelationSetsCommand(
        tenant_id=tenant_id,
        signal_references=(sig_a, sig_b, sig_c),
        correlation_window=timedelta(hours=1),
    )
    result = await service.form_correlation_sets(cmd)
    assert len(result.correlation_sets) == 1
    assert set(result.correlation_sets[0].signal_references) == {"a", "b"}
    assert result.uncorrelated_signal_count == 1


async def test_form_correlation_sets_outside_window_not_clustered(service, tenant_id, now):
    sig_a = make_signal_reference(
        tenant_id, subject_reference="asset-1", source_id="a", observed_at=now
    )
    sig_b = make_signal_reference(
        tenant_id, subject_reference="asset-1", source_id="b", observed_at=now + timedelta(hours=5)
    )
    cmd = FormRiskCorrelationSetsCommand(
        tenant_id=tenant_id,
        signal_references=(sig_a, sig_b),
        correlation_window=timedelta(hours=1),
    )
    result = await service.form_correlation_sets(cmd)
    assert result.correlation_sets == ()
    assert result.uncorrelated_signal_count == 2


async def test_form_correlation_sets_rejects_foreign_tenant_signal(
    service, tenant_id, other_tenant_id, now
):
    sig_a = make_signal_reference(
        tenant_id, subject_reference="asset-1", source_id="a", observed_at=now
    )
    sig_b = make_signal_reference(
        other_tenant_id, subject_reference="asset-1", source_id="b", observed_at=now
    )
    cmd = FormRiskCorrelationSetsCommand(
        tenant_id=tenant_id,
        signal_references=(sig_a, sig_b),
        correlation_window=timedelta(hours=1),
    )
    with pytest.raises(RiskTenantIsolationViolationError):
        await service.form_correlation_sets(cmd)


# -- delegated orchestration ---------------------------------------------------


async def test_recompute_score_delegates_to_profile_service(service, profile_service, tenant_id):
    profile = await _create_profile(profile_service, tenant_id)
    cmd = RecomputeEnterpriseRiskCommand(
        tenant_id=tenant_id,
        profile_id=profile_service_profile_id(profile),
        signals=(
            RiskDimensionSignal(
                dimension=RiskDimension.VULNERABILITY,
                signal_reference=make_signal_reference(tenant_id),
            ),
        ),
        weight_profile=make_weight_profile(),
    )
    updated = await service.recompute_score(cmd)
    assert updated.composite_score is not None


def profile_service_profile_id(profile):
    return RiskProfileId(UUID(profile.profile_id))


async def test_mitigate_profile_delegates_to_profile_service(service, profile_service, tenant_id):
    profile = await _create_profile(profile_service, tenant_id)
    cmd = MitigateEnterpriseRiskCommand(
        tenant_id=tenant_id, profile_id=profile_service_profile_id(profile)
    )
    updated = await service.mitigate_profile(cmd)
    assert updated.status == RiskProfileStatus.MITIGATED.value


async def test_generate_timeline_delegates_to_timeline_service(service, profile_service, tenant_id):
    profile = await _create_profile(profile_service, tenant_id)
    profile_id = profile_service_profile_id(profile)
    recompute_cmd = RecomputeEnterpriseRiskCommand(
        tenant_id=tenant_id,
        profile_id=profile_id,
        signals=(
            RiskDimensionSignal(
                dimension=RiskDimension.VULNERABILITY,
                signal_reference=make_signal_reference(tenant_id),
            ),
        ),
        weight_profile=make_weight_profile(),
    )
    await profile_service.recompute_score(recompute_cmd)
    timeline = await service.generate_timeline(
        GetRiskTimelineQuery(tenant_id=tenant_id, profile_id=profile_id)
    )
    assert timeline.profile_id == str(profile_id)


# -- escalation policy execution ------------------------------------------------


async def test_evaluate_escalation_true_for_critical_acknowledged_profile(
    service, profile_service, tenant_id
):
    profile = await _create_profile(profile_service, tenant_id)
    profile_id = profile_service_profile_id(profile)
    recompute_cmd = RecomputeEnterpriseRiskCommand(
        tenant_id=tenant_id,
        profile_id=profile_id,
        signals=(
            RiskDimensionSignal(
                dimension=RiskDimension.VULNERABILITY,
                signal_reference=make_signal_reference(tenant_id, raw_value=9.5),
            ),
        ),
        weight_profile=make_weight_profile(),
    )
    await profile_service.recompute_score(recompute_cmd)
    await profile_service.acknowledge(
        AcknowledgeEnterpriseRiskCommand(tenant_id=tenant_id, profile_id=profile_id)
    )

    decision = await service.evaluate_escalation(
        EvaluateRiskEscalationCommand(
            tenant_id=tenant_id,
            profile_id=profile_id,
            critical_threshold=NormalizedRiskScore(9.0),
        )
    )
    assert decision.should_escalate is True


async def test_evaluate_escalation_false_for_open_profile(service, profile_service, tenant_id):
    profile = await _create_profile(profile_service, tenant_id)
    profile_id = profile_service_profile_id(profile)
    decision = await service.evaluate_escalation(
        EvaluateRiskEscalationCommand(
            tenant_id=tenant_id,
            profile_id=profile_id,
            critical_threshold=NormalizedRiskScore(1.0),
        )
    )
    assert decision.should_escalate is False


async def test_evaluate_escalation_raises_for_missing_profile(service, tenant_id):
    with pytest.raises(EnterpriseRiskProfileNotFoundError):
        await service.evaluate_escalation(
            EvaluateRiskEscalationCommand(
                tenant_id=tenant_id,
                profile_id=RiskProfileId.generate(),
                critical_threshold=NormalizedRiskScore(9.0),
            )
        )


# -- acceptance expiry + lifecycle orchestration --------------------------------


async def test_evaluate_acceptance_expiry_closes_profile_when_expired(
    service, profile_service, tenant_id, now
):
    profile = await _create_profile(profile_service, tenant_id)
    profile_id = profile_service_profile_id(profile)
    await profile_service.accept(
        AcceptEnterpriseRiskCommand(
            tenant_id=tenant_id, profile_id=profile_id, expires_at=now + timedelta(days=1)
        )
    )

    decision = await service.evaluate_acceptance_expiry(
        EvaluateRiskAcceptanceExpiryCommand(
            tenant_id=tenant_id,
            profile_id=profile_id,
            critical_threshold=NormalizedRiskScore(9.9),
            now=now + timedelta(days=2),
        )
    )
    assert decision.expired is True
    assert decision.escalation_overrides is False
    assert decision.closed is True


async def test_evaluate_acceptance_expiry_not_expired_leaves_profile_untouched(
    service, profile_service, tenant_id, now
):
    profile = await _create_profile(profile_service, tenant_id)
    profile_id = profile_service_profile_id(profile)
    await profile_service.accept(
        AcceptEnterpriseRiskCommand(
            tenant_id=tenant_id, profile_id=profile_id, expires_at=now + timedelta(days=10)
        )
    )

    decision = await service.evaluate_acceptance_expiry(
        EvaluateRiskAcceptanceExpiryCommand(
            tenant_id=tenant_id,
            profile_id=profile_id,
            critical_threshold=NormalizedRiskScore(9.9),
            now=now + timedelta(days=1),
        )
    )
    assert decision.expired is False
    assert decision.closed is False


async def test_evaluate_acceptance_expiry_escalation_overrides_expiry(
    service, profile_service, tenant_id, now
):
    profile = await _create_profile(profile_service, tenant_id)
    profile_id = profile_service_profile_id(profile)
    recompute_cmd = RecomputeEnterpriseRiskCommand(
        tenant_id=tenant_id,
        profile_id=profile_id,
        signals=(
            RiskDimensionSignal(
                dimension=RiskDimension.VULNERABILITY,
                signal_reference=make_signal_reference(tenant_id, raw_value=9.8),
            ),
        ),
        weight_profile=make_weight_profile(),
    )
    await profile_service.recompute_score(recompute_cmd)
    await profile_service.accept(
        AcceptEnterpriseRiskCommand(
            tenant_id=tenant_id, profile_id=profile_id, expires_at=now + timedelta(days=1)
        )
    )

    decision = await service.evaluate_acceptance_expiry(
        EvaluateRiskAcceptanceExpiryCommand(
            tenant_id=tenant_id,
            profile_id=profile_id,
            critical_threshold=NormalizedRiskScore(9.0),
            now=now + timedelta(days=2),
        )
    )
    assert decision.escalation_overrides is True
    assert decision.closed is False


async def test_evaluate_acceptance_expiry_raises_when_not_accepted(
    service, profile_service, tenant_id, now
):
    profile = await _create_profile(profile_service, tenant_id)
    profile_id = profile_service_profile_id(profile)
    with pytest.raises(RiskProfileNotAcceptedError):
        await service.evaluate_acceptance_expiry(
            EvaluateRiskAcceptanceExpiryCommand(
                tenant_id=tenant_id,
                profile_id=profile_id,
                critical_threshold=NormalizedRiskScore(9.9),
                now=now,
            )
        )
