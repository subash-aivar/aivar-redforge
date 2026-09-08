"""Integration tests for SqlAlchemyMitreTechniqueIdentityAdapter (real
PostgreSQL) — read-only queries against the real `attack_techniques`
table (M22)."""

from __future__ import annotations

import pytest

from attack_pattern_intel.infrastructure.acl.mitre_technique_identity_adapter import (
    SqlAlchemyMitreTechniqueIdentityAdapter,
)
from tests.attack_pattern_intel.infrastructure.helpers import (
    random_technique_id,
    seed_attack_technique,
)

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_exists_true_for_seeded_technique(ap_session) -> None:
    technique_id = random_technique_id()
    await seed_attack_technique(ap_session, technique_id)
    adapter = SqlAlchemyMitreTechniqueIdentityAdapter(ap_session)
    assert await adapter.exists(technique_id) is True


@pytest.mark.asyncio
async def test_exists_false_for_unknown_technique(ap_session) -> None:
    adapter = SqlAlchemyMitreTechniqueIdentityAdapter(ap_session)
    assert await adapter.exists("T9999") is False


@pytest.mark.asyncio
async def test_get_snapshot_returns_descriptive_fields(ap_session) -> None:
    technique_id = random_technique_id()
    await seed_attack_technique(ap_session, technique_id, name="Command and Scripting Interpreter")
    adapter = SqlAlchemyMitreTechniqueIdentityAdapter(ap_session)
    snapshot = await adapter.get_snapshot(technique_id)
    assert snapshot is not None
    assert snapshot.technique_id == technique_id
    assert snapshot.name == "Command and Scripting Interpreter"
    assert snapshot.tactic_ids == ("TA0002",)
    assert snapshot.platforms == ("Windows",)
    assert snapshot.is_deprecated is False
    assert snapshot.is_revoked is False


@pytest.mark.asyncio
async def test_get_snapshot_none_for_unknown_technique(ap_session) -> None:
    adapter = SqlAlchemyMitreTechniqueIdentityAdapter(ap_session)
    snapshot = await adapter.get_snapshot("T9999")
    assert snapshot is None
