from __future__ import annotations

import pytest

from risk_engine.application.commands.risk_profile_commands import (
    AcceptEnterpriseRiskCommand,
    AcknowledgeEnterpriseRiskCommand,
    CloseEnterpriseRiskCommand,
    CreateEnterpriseRiskProfileCommand,
    MitigateEnterpriseRiskCommand,
    RecomputeEnterpriseRiskCommand,
    RiskDimensionSignal,
)
from risk_engine.application.exceptions import (
    EmptySignalsError,
    EnterpriseRiskProfileNotFoundError,
    InvalidSubjectReferenceError,
)
from risk_engine.application.services.enterprise_risk_profile_service import (
    EnterpriseRiskProfileApplicationService,
)
from risk_engine.domain.exceptions.domain_exceptions import InvalidRiskProfileTransition
from risk_engine.domain.value_objects.enums import RiskDimension, RiskProfileStatus
from risk_engine.domain.value_objects.identifiers import RiskProfileId
from tests.risk_engine.application.conftest import make_signal_reference


@pytest.fixture
def service(profile_repository, unit_of_work) -> EnterpriseRiskProfileApplicationService:
    return EnterpriseRiskProfileApplicationService(profile_repository, unit_of_work)


async def _create(service, tenant_id, subject_reference="asset-123"):
    cmd = CreateEnterpriseRiskProfileCommand(
        tenant_id=tenant_id,
        subject_reference=subject_reference,
        dimension=RiskDimension.VULNERABILITY,
        signal_reference=make_signal_reference(tenant_id, subject_reference=subject_reference),
    )
    return await service.create_profile(cmd)


class TestCreateEnterpriseRiskProfileCommand:
    async def test_creates_profile_with_normalized_contribution(
        self, service, tenant_id, unit_of_work
    ):
        dto = await _create(service, tenant_id)
        assert dto.tenant_id == str(tenant_id)
        assert dto.status == RiskProfileStatus.OPEN.value
        assert dto.composite_score is None
        assert len(dto.contributions) == 1
        assert dto.contributions[0].dimension == RiskDimension.VULNERABILITY.value
        assert dto.contributions[0].normalized_score == pytest.approx(7.5)
        assert unit_of_work.committed == 1

    async def test_rejects_blank_subject_reference(self, service, tenant_id):
        with pytest.raises(InvalidSubjectReferenceError):
            await _create(service, tenant_id, subject_reference="   ")


class TestRecomputeEnterpriseRiskCommand:
    async def test_recomputes_composite_score(self, service, tenant_id, weight_profile):
        created = await _create(service, tenant_id)
        profile_id = RiskProfileId(__import__("uuid").UUID(created.profile_id))
        cmd = RecomputeEnterpriseRiskCommand(
            tenant_id=tenant_id,
            profile_id=profile_id,
            signals=(
                RiskDimensionSignal(
                    dimension=RiskDimension.VULNERABILITY,
                    signal_reference=make_signal_reference(tenant_id, raw_value=8.0),
                ),
                RiskDimensionSignal(
                    dimension=RiskDimension.CLOUD,
                    signal_reference=make_signal_reference(tenant_id, raw_value=4.0),
                ),
            ),
            weight_profile=weight_profile,
        )
        dto = await service.recompute_score(cmd)
        assert dto.composite_score == pytest.approx(6.0)
        assert dto.weight_profile_id == "default:v1"
        assert len(dto.contributions) == 2

    async def test_rejects_empty_signals(self, service, tenant_id, weight_profile):
        created = await _create(service, tenant_id)
        profile_id = RiskProfileId(__import__("uuid").UUID(created.profile_id))
        cmd = RecomputeEnterpriseRiskCommand(
            tenant_id=tenant_id,
            profile_id=profile_id,
            signals=(),
            weight_profile=weight_profile,
        )
        with pytest.raises(EmptySignalsError):
            await service.recompute_score(cmd)

    async def test_raises_not_found_for_unknown_profile(self, service, tenant_id, weight_profile):
        cmd = RecomputeEnterpriseRiskCommand(
            tenant_id=tenant_id,
            profile_id=RiskProfileId.generate(),
            signals=(
                RiskDimensionSignal(
                    dimension=RiskDimension.VULNERABILITY,
                    signal_reference=make_signal_reference(tenant_id),
                ),
            ),
            weight_profile=weight_profile,
        )
        with pytest.raises(EnterpriseRiskProfileNotFoundError):
            await service.recompute_score(cmd)


class TestLifecycleTransitions:
    async def test_full_lifecycle_open_ack_mitigated_closed(self, service, tenant_id, now):
        created = await _create(service, tenant_id)
        pid = RiskProfileId(__import__("uuid").UUID(created.profile_id))

        ack = await service.acknowledge(AcknowledgeEnterpriseRiskCommand(tenant_id, pid))
        assert ack.status == RiskProfileStatus.ACKNOWLEDGED.value

        mitigated = await service.mitigate(MitigateEnterpriseRiskCommand(tenant_id, pid))
        assert mitigated.status == RiskProfileStatus.MITIGATED.value

        closed = await service.close(CloseEnterpriseRiskCommand(tenant_id, pid))
        assert closed.status == RiskProfileStatus.CLOSED.value

    async def test_full_lifecycle_open_ack_accepted_closed(self, service, tenant_id, now):
        created = await _create(service, tenant_id)
        pid = RiskProfileId(__import__("uuid").UUID(created.profile_id))

        await service.acknowledge(AcknowledgeEnterpriseRiskCommand(tenant_id, pid))
        accepted = await service.accept(AcceptEnterpriseRiskCommand(tenant_id, pid, expires_at=now))
        assert accepted.status == RiskProfileStatus.ACCEPTED.value
        assert accepted.accepted_expires_at == now

        closed = await service.close(CloseEnterpriseRiskCommand(tenant_id, pid))
        assert closed.status == RiskProfileStatus.CLOSED.value

    async def test_invalid_transition_propagates_domain_error(self, service, tenant_id):
        created = await _create(service, tenant_id)
        pid = RiskProfileId(__import__("uuid").UUID(created.profile_id))
        await service.close(CloseEnterpriseRiskCommand(tenant_id, pid))
        with pytest.raises(InvalidRiskProfileTransition):
            await service.acknowledge(AcknowledgeEnterpriseRiskCommand(tenant_id, pid))

    async def test_transition_on_unknown_profile_raises_not_found(self, service, tenant_id):
        with pytest.raises(EnterpriseRiskProfileNotFoundError):
            await service.acknowledge(
                AcknowledgeEnterpriseRiskCommand(tenant_id, RiskProfileId.generate())
            )


class TestTenantIsolation:
    async def test_wrong_tenant_cannot_transition_profile(
        self, service, tenant_id, other_tenant_id
    ):
        created = await _create(service, tenant_id)
        pid = RiskProfileId(__import__("uuid").UUID(created.profile_id))
        with pytest.raises(EnterpriseRiskProfileNotFoundError):
            await service.acknowledge(AcknowledgeEnterpriseRiskCommand(other_tenant_id, pid))

    async def test_wrong_tenant_cannot_recompute(
        self, service, tenant_id, other_tenant_id, weight_profile
    ):
        created = await _create(service, tenant_id)
        pid = RiskProfileId(__import__("uuid").UUID(created.profile_id))
        cmd = RecomputeEnterpriseRiskCommand(
            tenant_id=other_tenant_id,
            profile_id=pid,
            signals=(
                RiskDimensionSignal(
                    dimension=RiskDimension.VULNERABILITY,
                    signal_reference=make_signal_reference(other_tenant_id),
                ),
            ),
            weight_profile=weight_profile,
        )
        with pytest.raises(EnterpriseRiskProfileNotFoundError):
            await service.recompute_score(cmd)
