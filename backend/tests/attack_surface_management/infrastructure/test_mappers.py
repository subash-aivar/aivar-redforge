"""Unit tests for the shared mapper helpers — no DB needed."""

from __future__ import annotations

from attack_surface_management.infrastructure.persistence.mappers import new_uuid


def test_new_uuid_returns_unique_values() -> None:
    a, b = new_uuid(), new_uuid()
    assert a != b
