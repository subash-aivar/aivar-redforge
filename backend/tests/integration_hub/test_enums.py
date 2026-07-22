from __future__ import annotations

import pytest

from integration_hub.domain.value_objects.enums import ConnectorFailureMode, ConnectorType


@pytest.mark.parametrize("value", list(ConnectorType))
def test_types(value: ConnectorType) -> None:
    assert value.value == value.name


def test_fifteen_types() -> None:
    assert len(ConnectorType) == 15


@pytest.mark.parametrize("value", list(ConnectorFailureMode))
def test_failure_modes(value: ConnectorFailureMode) -> None:
    assert value.value == value.name


def test_eight_failure_modes() -> None:
    assert len(ConnectorFailureMode) == 8
