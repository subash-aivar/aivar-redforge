from __future__ import annotations

from uuid import uuid4

import pytest

from integration_hub.domain.aggregates.connector_registration import ConnectorRegistration
from integration_hub.domain.exceptions.domain_exceptions import DomainInvariantViolation
from integration_hub.domain.services.credential_resolution_service import (
    CredentialResolutionService,
)
from integration_hub.domain.value_objects.enums import ConnectorType
from integration_hub.domain.value_objects.identifiers import EntityId
from integration_hub.infrastructure.vault.in_memory_vault import InMemoryCredentialVault


def test_rejects_secret_config() -> None:
    with pytest.raises(DomainInvariantViolation):
        ConnectorRegistration.register(
            EntityId.generate(),
            ConnectorType.IDENTITY_OKTA,
            "okta",
            "vault/okta",
            "OAUTH_CLIENT",
            configuration={"api_key": "x"},
        )


@pytest.mark.asyncio
async def test_resolve_in_memory_only() -> None:
    vault = InMemoryCredentialVault()
    vault.put("k1", "super-secret")
    svc = CredentialResolutionService(vault)
    tenant = str(uuid4())
    from integration_hub.domain.value_objects.credentials import CredentialRef

    resolved = await svc.resolve(CredentialRef("k1", tenant, "API_KEY"), tenant)
    assert resolved.secret_value == "super-secret"
