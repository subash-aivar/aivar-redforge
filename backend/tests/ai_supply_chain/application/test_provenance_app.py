from __future__ import annotations

import hashlib
from uuid import uuid4

import pytest

from ai_supply_chain.application.commands.supply_chain_commands import (
    BuildMBOMCommand,
    RecordModelProvenanceCommand,
    VerifyModelProvenanceCommand,
)
from ai_supply_chain.domain.value_objects.identifiers import TenantId
from ai_supply_chain.infrastructure.container import SupplyChainContainer
from tests.ai_supply_chain.conftest import ENGINEER


@pytest.mark.asyncio
async def test_record_verify_mbom_flow(
    container: SupplyChainContainer, tenant_id: TenantId
) -> None:
    content = b"artifact-v1"
    container.hash_port.put_artifact("mem://m1", content)
    digest = hashlib.sha256(content).hexdigest()
    dto = await container.provenance_service.record(
        RecordModelProvenanceCommand(
            tenant_id=tenant_id,
            asset_id=uuid4(),
            model_origin="OpenSourceRegistry",
            artifact_size_bytes=len(content),
            actor_roles=ENGINEER,
        )
    )
    verified = await container.provenance_service.verify(
        VerifyModelProvenanceCommand(
            tenant_id=tenant_id,
            provenance_id=__import__("uuid").UUID(dto.provenance_id),
            retrieval_uri="mem://m1",
            provider_reported_checksum=digest,
            actor_roles=ENGINEER,
        )
    )
    assert verified.integrity_status == "Verified"
    mbom = await container.mbom_service.build(
        BuildMBOMCommand(
            tenant_id=tenant_id,
            provenance_id=__import__("uuid").UUID(dto.provenance_id),
            components=(
                {
                    "component_type": "BaseModel",
                    "name": "base",
                    "version": "1",
                    "source": "hf",
                    "checksum": "x",
                },
            ),
            actor_roles=ENGINEER,
        )
    )
    assert mbom.completed is True
