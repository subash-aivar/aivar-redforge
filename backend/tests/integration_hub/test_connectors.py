from __future__ import annotations

import pytest

from integration_hub.domain.value_objects.enums import ConnectorFailureMode
from integration_hub.infrastructure.connectors.in_memory_action_connector import (
    InMemoryActionConnector,
)


@pytest.mark.parametrize("mode", list(ConnectorFailureMode))
@pytest.mark.asyncio
async def test_all_failure_modes(mode: ConnectorFailureMode) -> None:
    c = InMemoryActionConnector(fail_mode=mode)
    result = await c.execute("act", {}, "t1")
    assert result.success is False
    assert result.failure_mode == mode


@pytest.mark.asyncio
async def test_success_path() -> None:
    c = InMemoryActionConnector()
    result = await c.execute("contain_host", {"host": "h1"}, "t1")
    assert result.success is True
    assert result.external_reference
