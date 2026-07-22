from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from autonomous_intelligence.application.commands.intelligence_commands import (
    CreateIntelligenceSuggestion,
)
from autonomous_intelligence.infrastructure.container import AutonomousIntelligenceContainer


@pytest.mark.asyncio
async def test_expiry_worker() -> None:
    c = AutonomousIntelligenceContainer()
    tenant = uuid4()
    created = await c.app.create_suggestion(
        CreateIntelligenceSuggestion(
            tenant,
            "playbook",
            None,
            "playbook_synthesis",
            {},
            "m1",
            1,
            0.80,
            (),
            "synth",
            ("system",),
        )
    )
    s = await c.suggestions.find_by_id(UUID(created.suggestion_id), c.app._tenant(tenant))
    assert s is not None
    s.review_deadline_at = datetime.now(UTC) - timedelta(minutes=1)
    await c.suggestions.save(s, c.app._tenant(tenant))
    n = await c.expiry_worker.tick()
    assert n == 1
    s2 = await c.suggestions.find_by_id(UUID(created.suggestion_id), c.app._tenant(tenant))
    assert s2 is not None
    assert s2.status.value == "expired"


@pytest.mark.asyncio
async def test_scheduler() -> None:
    c = AutonomousIntelligenceContainer()
    result = await c.scheduler.tick_all(uuid4())
    assert "expired" in result
