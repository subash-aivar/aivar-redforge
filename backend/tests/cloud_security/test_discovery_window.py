from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from cloud_security.domain.exceptions.domain_exceptions import InvalidDiscoveryWindowError
from cloud_security.domain.value_objects.discovery_window import DiscoveryWindow

NOW = datetime.now(UTC)


def test_end_must_be_after_start() -> None:
    with pytest.raises(InvalidDiscoveryWindowError):
        DiscoveryWindow(start=NOW, end=NOW)
    with pytest.raises(InvalidDiscoveryWindowError):
        DiscoveryWindow(start=NOW, end=NOW - timedelta(seconds=1))


def test_duration() -> None:
    window = DiscoveryWindow(start=NOW - timedelta(hours=1), end=NOW)
    assert window.duration == timedelta(hours=1)
