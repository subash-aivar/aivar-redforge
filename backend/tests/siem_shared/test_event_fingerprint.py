from __future__ import annotations

import pytest

from siem_shared.domain.exceptions.domain_exceptions import InvalidFingerprintError
from siem_shared.domain.value_objects.event_fingerprint import EventFingerprint


def test_rejects_empty_value() -> None:
    with pytest.raises(InvalidFingerprintError):
        EventFingerprint("")


def test_rejects_whitespace_only_value() -> None:
    with pytest.raises(InvalidFingerprintError):
        EventFingerprint("   ")


def test_compute_is_deterministic_idempotent_reingestion() -> None:
    """Re-ingestion of the same source event resolves to the same
    fingerprint (M37 §2.1)."""
    a = EventFingerprint.compute("okta", "identity", "tenant-1", "2026-01-01T00:00:00+00:00")
    b = EventFingerprint.compute("okta", "identity", "tenant-1", "2026-01-01T00:00:00+00:00")
    assert a == b


def test_compute_differs_for_different_inputs() -> None:
    a = EventFingerprint.compute("okta", "identity", "tenant-1", "t1")
    b = EventFingerprint.compute("okta", "identity", "tenant-2", "t1")
    assert a != b


def test_str_returns_value() -> None:
    fp = EventFingerprint("abc123")
    assert str(fp) == "abc123"
