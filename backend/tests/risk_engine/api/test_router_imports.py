"""Minimal API router import tests — mirrors
`tests/credential_vault/api/test_router_imports.py`."""

from __future__ import annotations


def test_risk_engine_routers_import() -> None:
    from risk_engine.api.v1 import router

    assert router.routes

    from risk_engine.api.v1 import risk_correlations, risk_profiles

    assert risk_profiles.risk_profiles_router.routes
    assert risk_correlations.risk_correlations_router.routes


def test_risk_engine_exception_handlers_import() -> None:
    from risk_engine.api.exception_handlers import register_risk_engine_exception_handlers

    assert callable(register_risk_engine_exception_handlers)


def test_risk_engine_container_import() -> None:
    from risk_engine.infrastructure.container import RiskEngineContainer

    assert callable(RiskEngineContainer)
