"""Integration test proving the production container wires a real
evidence validator (not a seeded test stub) and produces a working
application service end to end."""

from __future__ import annotations

import pytest

from ioc_intelligence.application._auth import IocIntelRole
from ioc_intelligence.application.commands.ioc_commands import (
    ObserveGlobalIocCommand,
    SourceAttributionInput,
)
from ioc_intelligence.infrastructure.acl.infrastructure_evidence_validation_adapter import (
    InfrastructureEvidenceValidationAdapter,
)
from ioc_intelligence.infrastructure.container import IocIntelContainer
from redforge.application.evidence_existence.sqlalchemy_evidence_entity_existence_service import (
    SqlAlchemyEvidenceEntityExistenceService,
)
from redforge.shared.ioc_vocabulary import ProviderName
from tests.ioc_intelligence.infrastructure.helpers import random_ip

pytestmark = pytest.mark.integration

PLATFORM_ADMIN = (IocIntelRole.PLATFORM_ADMIN.value,)


@pytest.mark.asyncio
async def test_container_wires_real_evidence_validation_adapter(ioc_session_factory) -> None:
    container = IocIntelContainer(ioc_session_factory)
    session = container.new_session()
    try:
        service = container.build_service(session)
        # The wired-in validator must be the real infrastructure adapter
        # backed by the real SqlAlchemyEvidenceEntityExistenceService —
        # never a seeded/synthetic allow-list stub.
        validator = service._evidence
        assert isinstance(validator, InfrastructureEvidenceValidationAdapter)
        assert isinstance(validator._entity_existence, SqlAlchemyEvidenceEntityExistenceService)

        dto = await service.observe_global_ioc(
            ObserveGlobalIocCommand(
                ioc_type="ip",
                raw_value=random_ip(),
                source_attributions=(
                    SourceAttributionInput(
                        source_system=ProviderName.ALIENVAULT_OTX.value,
                        external_id="pulse-1",
                        observed_at="2026-08-05T00:00:00+00:00",
                        weight_applied=0.9,
                        confidence="high",
                    ),
                ),
                actor_roles=PLATFORM_ADMIN,
            )
        )
        assert dto.ioc_id
    finally:
        await session.close()
