from __future__ import annotations

import pytest

from attack_surface_management.application.commands.network_range_commands import (
    ActivateNetworkRangeCommand,
    FormNetworkRangeCommand,
    RecordNetworkRangeAssetCountCommand,
    RetireNetworkRangeCommand,
)
from attack_surface_management.application.exceptions import NetworkRangeNotFoundError
from attack_surface_management.application.services.network_range_application_service import (
    NetworkRangeApplicationService,
)
from attack_surface_management.domain.value_objects.cidr_block import CidrBlock
from attack_surface_management.domain.value_objects.identifiers import NetworkRangeId


@pytest.fixture
def service(network_range_repository, unit_of_work) -> NetworkRangeApplicationService:
    return NetworkRangeApplicationService(network_range_repository, unit_of_work)


async def _form(service, tenant_id) -> object:
    return await service.form_network_range(
        FormNetworkRangeCommand(tenant_id=tenant_id, cidr=CidrBlock("10.0.0.0/24"))
    )


def _range_id(dto) -> NetworkRangeId:
    import uuid

    return NetworkRangeId(uuid.UUID(dto.range_id))


class TestFormNetworkRange:
    async def test_forms_and_persists(self, service, tenant_id, unit_of_work):
        dto = await _form(service, tenant_id)
        assert dto.tenant_id == str(tenant_id)
        assert dto.cidr == "10.0.0.0/24"
        assert dto.lifecycle_state == "discovered"
        assert dto.asset_count == 0
        assert unit_of_work.committed == 1


class TestAssetCountAndLifecycle:
    async def test_record_asset_count(self, service, tenant_id):
        dto = await _form(service, tenant_id)
        updated = await service.record_asset_count(
            RecordNetworkRangeAssetCountCommand(
                tenant_id=tenant_id, range_id=_range_id(dto), count=12
            )
        )
        assert updated.asset_count == 12

    async def test_activate_then_retire(self, service, tenant_id):
        dto = await _form(service, tenant_id)
        range_id = _range_id(dto)
        active = await service.activate(
            ActivateNetworkRangeCommand(tenant_id=tenant_id, range_id=range_id)
        )
        assert active.lifecycle_state == "active"
        retired = await service.retire(
            RetireNetworkRangeCommand(tenant_id=tenant_id, range_id=range_id)
        )
        assert retired.lifecycle_state == "retired"


class TestNotFound:
    async def test_not_found_raises(self, service, tenant_id):
        with pytest.raises(NetworkRangeNotFoundError):
            await service.activate(
                ActivateNetworkRangeCommand(tenant_id=tenant_id, range_id=NetworkRangeId.generate())
            )
