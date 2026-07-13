"""Regression test for a real M16 defect found during the independent
security review: NetworkMonitoringPolicyService.create() called
EntityId.from_string(target_asset_id) unguarded — a malformed
target_asset_id raised a bare ValueError, which is not a RedForgeError
and therefore fell through to an unhandled 500 instead of a controlled
4xx (every other policy method already wrapped this the same way
`_get()` does). Fixed by validating target_asset_id and raising
ValidationError, matching the rest of this service's error discipline.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redforge.application.network_security.policy_service import (
    NetworkMonitoringPolicyService,
)
from redforge.core.exceptions import ValidationError
from redforge.domain.network_security.value_objects import (
    NetworkValidationProfile,
    ValidationCadence,
)
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio

_DB_URL = "postgresql+asyncpg://redforge:redforge@localhost:5432/redforge_test"


@pytest.fixture
async def session_factory():
    engine = create_async_engine(_DB_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


async def test_malformed_target_asset_id_raises_controlled_validation_error(
    session_factory,
) -> None:
    service = NetworkMonitoringPolicyService(session_factory)
    with pytest.raises(ValidationError):
        await service.create(
            organization_id=str(EntityId.generate()),
            target_asset_id="not-a-real-ulid",
            requester_user_id=str(EntityId.generate()),
            profile=NetworkValidationProfile.NETWORK_BASELINE,
            cadence=ValidationCadence.DAILY,
        )


async def test_empty_target_asset_id_raises_controlled_validation_error(
    session_factory,
) -> None:
    service = NetworkMonitoringPolicyService(session_factory)
    with pytest.raises(ValidationError):
        await service.create(
            organization_id=str(EntityId.generate()),
            target_asset_id="",
            requester_user_id=str(EntityId.generate()),
            profile=NetworkValidationProfile.NETWORK_BASELINE,
            cadence=ValidationCadence.DAILY,
        )
