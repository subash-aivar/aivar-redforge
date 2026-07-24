from __future__ import annotations

import pytest

from redforge.shared.identifiers import EntityId
from siem_shared.domain.exceptions.domain_exceptions import (
    EmptyVendorError,
    MissingConnectorIdError,
)
from siem_shared.domain.value_objects.event_source import EventSource, EventSourceType


def test_non_connector_source_needs_no_connector_id() -> None:
    source = EventSource(source_type=EventSourceType.AGENT, vendor="osquery")
    assert source.source_connector_id is None


def test_connector_source_requires_connector_id() -> None:
    with pytest.raises(MissingConnectorIdError):
        EventSource(source_type=EventSourceType.CONNECTOR, vendor="okta")


def test_connector_source_with_connector_id_succeeds() -> None:
    connector_id = EntityId.generate()
    source = EventSource(
        source_type=EventSourceType.CONNECTOR,
        vendor="okta",
        source_connector_id=connector_id,
    )
    assert source.source_connector_id == connector_id


def test_rejects_blank_vendor() -> None:
    with pytest.raises(EmptyVendorError):
        EventSource(source_type=EventSourceType.CLOUD, vendor="  ")
