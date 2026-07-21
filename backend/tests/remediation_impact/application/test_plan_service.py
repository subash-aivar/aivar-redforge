from __future__ import annotations

from uuid import uuid4

import pytest

from remediation_impact.application.commands.plan_commands import (
    CommitExposureReductionPlanCommand,
    GenerateExposureReductionPlanCommand,
    RemediationCandidateInput,
)
from remediation_impact.application.exceptions import ApplicationForbiddenError
from remediation_impact.infrastructure.acl.exposure_score_query_adapter import (
    StaticExposureScoreQueryAdapter,
)
from remediation_impact.infrastructure.container import RemediationImpactContainer

ANALYST = ("exposure:analyst",)
VIEWER = ("exposure:viewer",)
SIM_READER = ("exposure:simulation_reader",)


@pytest.fixture
def container() -> RemediationImpactContainer:
    scores = {"a1": 8.0, "a2": 6.0}
    return RemediationImpactContainer(
        score_port=StaticExposureScoreQueryAdapter(scores=scores, version=2)
    )


@pytest.mark.asyncio
async def test_generate_commit_list(container: RemediationImpactContainer) -> None:
    tenant = uuid4()
    dto = await container.plan_service.generate(
        GenerateExposureReductionPlanCommand(
            tenant_id=tenant,
            candidate_remediations=(
                RemediationCandidateInput("r1", ("a1",), (), 2.0),
                RemediationCandidateInput("r2", ("a2",), (), 1.0),
            ),
            plan_budget=2,
            actor_roles=ANALYST,
        )
    )
    assert dto.status == "Generated"
    assert dto.algorithm == "GreedyMarginalContribution"
    assert dto.score_input_version == 2
    committed = await container.plan_service.commit(
        CommitExposureReductionPlanCommand(
            tenant_id=tenant,
            plan_id=__import__("uuid").UUID(dto.plan_id),
            committed_by="analyst@aivar",
            actor_roles=ANALYST,
        )
    )
    assert committed.status == "Committed"
    listed = await container.plan_service.list_plans(tenant, SIM_READER)
    assert len(listed) == 1


@pytest.mark.asyncio
async def test_viewer_cannot_generate(container: RemediationImpactContainer) -> None:
    with pytest.raises(ApplicationForbiddenError):
        await container.plan_service.generate(
            GenerateExposureReductionPlanCommand(
                tenant_id=uuid4(),
                candidate_remediations=(RemediationCandidateInput("r1", ("a1",), (), 1.0),),
                actor_roles=VIEWER,
            )
        )


@pytest.mark.asyncio
async def test_simulation_reader_can_read(container: RemediationImpactContainer) -> None:
    tenant = uuid4()
    dto = await container.plan_service.generate(
        GenerateExposureReductionPlanCommand(
            tenant_id=tenant,
            candidate_remediations=(RemediationCandidateInput("r1", ("a1",), (), 1.0),),
            actor_roles=ANALYST,
        )
    )
    got = await container.plan_service.get(tenant, __import__("uuid").UUID(dto.plan_id), SIM_READER)
    assert got.plan_id == dto.plan_id
