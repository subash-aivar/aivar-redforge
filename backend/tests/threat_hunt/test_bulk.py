from __future__ import annotations

from uuid import uuid4

import pytest

from redforge.shared.identifiers import EntityId
from threat_hunt.application.ports.i_llm_inference_port import HuntLLMPrompt
from threat_hunt.domain.exceptions.domain_exceptions import TenantIsolationViolation
from threat_hunt.domain.value_objects.enums import DetectionRuleFormat, ThreatHuntCandidateStatus
from threat_hunt.infrastructure.acl.m33_anomaly_translator import (
    AnomalySignalDetectedPayload,
    M33AnomalyTranslator,
)
from threat_hunt.infrastructure.container import ThreatHuntContainer
from threat_hunt.infrastructure.llm.in_memory_llm import InMemoryHuntLLMAdapter


@pytest.mark.parametrize("status", list(ThreatHuntCandidateStatus))
def test_statuses(status: ThreatHuntCandidateStatus) -> None:
    assert isinstance(status.value, str)


@pytest.mark.parametrize("fmt", list(DetectionRuleFormat))
def test_formats(fmt: DetectionRuleFormat) -> None:
    assert fmt.value == fmt.name.lower()


def test_acl() -> None:
    sig = M33AnomalyTranslator().translate(AnomalySignalDetectedPayload("t", "s1", 0.9, "T1059"))
    assert sig is not None


@pytest.mark.asyncio
async def test_llm_tenant_isolation() -> None:
    llm = InMemoryHuntLLMAdapter()
    t = uuid4()
    with pytest.raises(TenantIsolationViolation):
        await llm.generate(HuntLLMPrompt(t, "task", "ctx"), uuid4())


@pytest.mark.asyncio
async def test_scheduler() -> None:
    c = ThreatHuntContainer()
    n = await c.scheduler.tick(EntityId.generate())
    assert n == 1
