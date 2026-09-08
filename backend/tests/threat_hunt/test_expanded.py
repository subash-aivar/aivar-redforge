from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI, Header
from fastapi.testclient import TestClient

from redforge.api.dependencies import get_organization_service
from redforge.api.security import TenantContext, get_tenant_context
from redforge.domain.identity.value_objects import MembershipRole, Permission
from redforge.shared.identifiers import EntityId
from threat_hunt.api.dependencies import get_container
from threat_hunt.api.v1 import router
from threat_hunt.application.commands.hunt_commands import (
    GenerateThreatHuntCandidate,
    PromoteThreatHuntCandidate,
    RejectThreatHuntCandidate,
)
from threat_hunt.application.ports.i_llm_inference_port import HuntLLMPrompt
from threat_hunt.domain.exceptions.domain_exceptions import (
    DomainInvariantViolation,
    TenantIsolationViolation,
)
from threat_hunt.domain.value_objects.enums import DetectionRuleFormat, ThreatHuntCandidateStatus
from threat_hunt.domain.value_objects.identifiers import (
    AnomalySignalRef,
    AttckTechniqueRef,
)
from threat_hunt.infrastructure.acl.m33_anomaly_translator import (
    AnomalySignalDetectedPayload,
    M33AnomalyTranslator,
)
from threat_hunt.infrastructure.container import ThreatHuntContainer
from threat_hunt.infrastructure.llm.in_memory_llm import InMemoryHuntLLMAdapter


@pytest.mark.parametrize("fmt", list(DetectionRuleFormat))
def test_formats(fmt: DetectionRuleFormat) -> None:
    assert isinstance(fmt.value, str)


@pytest.mark.parametrize("st", list(ThreatHuntCandidateStatus))
def test_statuses(st: ThreatHuntCandidateStatus) -> None:
    assert isinstance(st.value, str)


@pytest.mark.parametrize("strength", [0.1, 0.2, 0.4, 0.6, 0.8, 1.0])
def test_acl(strength: float) -> None:
    assert (
        M33AnomalyTranslator().translate(AnomalySignalDetectedPayload("t", "s1", strength, "T1059"))
        is not None
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("conf", [0.55, 0.65, 0.75, 0.85, 0.95])
async def test_generate_matrix(conf: float) -> None:
    c = ThreatHuntContainer()
    dto = await c.app.generate(
        GenerateThreatHuntCandidate(
            EntityId.generate(),
            ("s1",),
            ("T1059",),
            "title: draft",
            conf,
            ("system",),
        )
    )
    assert dto.confidence_score == conf


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(8))
async def test_promote_matrix(i: int) -> None:
    c = ThreatHuntContainer()
    tenant = EntityId.generate()
    created = await c.app.generate(
        GenerateThreatHuntCandidate(tenant, ("s1",), ("T1059",), "title: draft", 0.8, ("system",))
    )
    dto = await c.app.promote(
        PromoteThreatHuntCandidate(
            tenant,
            UUID(created.candidate_id),
            "eng",
            uuid4(),
            ("soc:detection_engineer",),
        )
    )
    assert dto.status == "promoted"


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(8))
async def test_reject_matrix(i: int) -> None:
    c = ThreatHuntContainer()
    tenant = EntityId.generate()
    created = await c.app.generate(
        GenerateThreatHuntCandidate(tenant, ("s1",), ("T1059",), "title: draft", 0.8, ("system",))
    )
    dto = await c.app.reject(
        RejectThreatHuntCandidate(
            tenant,
            UUID(created.candidate_id),
            "eng",
            "noise",
            ("soc:detection_engineer",),
        )
    )
    assert dto.status == "rejected"


@pytest.mark.asyncio
async def test_promote_requires_reviewed_by() -> None:
    c = ThreatHuntContainer()
    tenant = EntityId.generate()
    created = await c.app.generate(
        GenerateThreatHuntCandidate(tenant, ("s1",), ("T1059",), "title: draft", 0.8, ("system",))
    )
    cand = await c.candidates.find_by_id(UUID(created.candidate_id), tenant)
    assert cand is not None
    with pytest.raises(DomainInvariantViolation):
        cand.promote(tenant, "", ("soc:detection_engineer",), uuid4())


@pytest.mark.asyncio
@pytest.mark.parametrize("i", range(5))
async def test_llm_isolation(i: int) -> None:
    llm = InMemoryHuntLLMAdapter()
    with pytest.raises(TenantIsolationViolation):
        await llm.generate(HuntLLMPrompt(uuid4(), "t", "c"), uuid4())


class _OrgStub:
    """Stubs `OrganizationService.get_by_id` so `require_permission`'s
    suspension check doesn't need a real `organizations` table row —
    matches `tests/attack_surface_management/api/conftest.py`'s
    `_OrgStub` precedent."""

    async def get_by_id(self, organization_id: str) -> object:
        class _Org:
            status = "active"

        return _Org()


def _override_tenant_context(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
) -> TenantContext:
    return TenantContext(
        user_id=str(uuid4()),
        email="threat-hunt-test@example.com",
        organization_id=x_tenant_id,
        role=MembershipRole.OWNER,
        permissions=frozenset(Permission),
    )


@pytest.fixture()
def client() -> TestClient:
    app = FastAPI()
    app.include_router(router)
    c = ThreatHuntContainer()
    app.dependency_overrides[get_container] = lambda: c
    app.dependency_overrides[get_tenant_context] = _override_tenant_context
    app.dependency_overrides[get_organization_service] = lambda: _OrgStub()
    return TestClient(app)


@pytest.mark.parametrize("i", range(5))
def test_api_health(client: TestClient, i: int) -> None:
    assert client.get("/threat-hunt/health").status_code == 200


@pytest.mark.parametrize("conf", [0.6, 0.7, 0.8, 0.9])
def test_api_generate(client: TestClient, conf: float) -> None:
    r = client.post(
        "/threat-hunt/candidates",
        headers={"X-Tenant-Id": str(EntityId.generate())},
        json={"anomaly_signal_ids": ["s1"], "confidence_score": conf},
    )
    assert r.status_code == 201


def test_signal_ref_vo() -> None:
    assert AnomalySignalRef("s", "analytics").signal_id == "s"
    assert AttckTechniqueRef("T1059", "Command").technique_id == "T1059"
