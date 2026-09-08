"""Minimal API router import tests — mirrors
`tests/risk_engine/api/test_router_imports.py`."""

from __future__ import annotations


def test_threat_actor_intel_router_imports() -> None:
    from threat_actor_intel.api.v1 import router

    assert router.routes

    from threat_actor_intel.api.v1 import threat_actors

    assert threat_actors.threat_actors_router.routes


def test_threat_actor_intel_exception_handlers_import() -> None:
    from threat_actor_intel.api.exception_handlers import (
        register_threat_actor_intel_exception_handlers,
    )

    assert callable(register_threat_actor_intel_exception_handlers)


def test_threat_actor_intel_container_import() -> None:
    from threat_actor_intel.infrastructure.container import ThreatActorIntelContainer

    assert callable(ThreatActorIntelContainer)
