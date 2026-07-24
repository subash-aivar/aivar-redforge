from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from redforge.shared.identifiers import EntityId
from threat_hunt.application.commands.hunt_commands import (
    GenerateThreatHuntCandidate,
    PromoteThreatHuntCandidate,
    RejectThreatHuntCandidate,
)
from threat_hunt.domain.exceptions.domain_exceptions import AuthorizationDenied
from threat_hunt.infrastructure.container import ThreatHuntContainer


@pytest.mark.asyncio
async def test_generate_and_promote() -> None:
    c = ThreatHuntContainer()
    tenant = EntityId.generate()
    created = await c.app.generate(
        GenerateThreatHuntCandidate(tenant, ("s1",), ("T1059",), "logic", 0.9, ("system",))
    )
    assert created.status == "candidate"
    promoted = await c.app.promote(
        PromoteThreatHuntCandidate(
            tenant,
            UUID(created.candidate_id),
            "eng",
            uuid4(),
            ("soc:detection_engineer",),
        )
    )
    assert promoted.status == "promoted"
    assert promoted.anomaly_signal_count == 1


@pytest.mark.asyncio
async def test_promote_requires_role() -> None:
    c = ThreatHuntContainer()
    tenant = EntityId.generate()
    created = await c.app.generate(
        GenerateThreatHuntCandidate(tenant, ("s1",), ("T1059",), "logic", 0.9, ("system",))
    )
    with pytest.raises(AuthorizationDenied):
        await c.app.promote(
            PromoteThreatHuntCandidate(
                tenant, UUID(created.candidate_id), "x", uuid4(), ("ai:operator",)
            )
        )


@pytest.mark.asyncio
async def test_reject() -> None:
    c = ThreatHuntContainer()
    tenant = EntityId.generate()
    created = await c.app.generate(
        GenerateThreatHuntCandidate(tenant, ("s1",), ("T1059",), "logic", 0.9, ("system",))
    )
    rejected = await c.app.reject(
        RejectThreatHuntCandidate(
            tenant,
            UUID(created.candidate_id),
            "eng",
            "noise",
            ("soc:detection_engineer",),
        )
    )
    assert rejected.status == "rejected"
