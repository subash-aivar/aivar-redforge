from __future__ import annotations

import pytest

from playbook.domain.value_objects.enums import (
    ActionImpactLevel,
    ConnectorType,
    KillSwitchState,
    PlaybookStatus,
    TriggerSourceContext,
    VersionStatus,
)
from playbook.domain.value_objects.enums import (
    TestOutcome as PlaybookTestOutcome,
)


@pytest.mark.parametrize("value", list(ActionImpactLevel))
def test_impact_levels(value: ActionImpactLevel) -> None:
    assert value.value == value.name


@pytest.mark.parametrize("value", list(ConnectorType))
def test_connector_types(value: ConnectorType) -> None:
    assert isinstance(value.value, str)


@pytest.mark.parametrize("value", list(PlaybookStatus))
def test_playbook_status(value: PlaybookStatus) -> None:
    assert value.value == value.name


@pytest.mark.parametrize("value", list(VersionStatus))
def test_version_status(value: VersionStatus) -> None:
    assert value.value == value.name


@pytest.mark.parametrize("value", list(PlaybookTestOutcome))
def test_test_outcome(value: PlaybookTestOutcome) -> None:
    assert value.value == value.name


@pytest.mark.parametrize("value", list(KillSwitchState))
def test_kill_switch_state(value: KillSwitchState) -> None:
    assert value.value == value.name


@pytest.mark.parametrize("value", list(TriggerSourceContext))
def test_trigger_source(value: TriggerSourceContext) -> None:
    assert value.value == value.name


def test_connector_type_count() -> None:
    assert len(ConnectorType) == 15
