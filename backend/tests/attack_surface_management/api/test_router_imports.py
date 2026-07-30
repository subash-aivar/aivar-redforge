"""Minimal API router import tests — mirrors
`tests/risk_engine/api/test_router_imports.py`."""

from __future__ import annotations


def test_attack_surface_management_routers_import() -> None:
    from attack_surface_management.api.v1 import router

    assert router.routes

    from attack_surface_management.api.v1 import assets, network_ranges

    assert assets.assets_router.routes
    assert network_ranges.network_ranges_router.routes


def test_attack_surface_management_exception_handlers_import() -> None:
    from attack_surface_management.api.exception_handlers import (
        register_attack_surface_management_exception_handlers,
    )

    assert callable(register_attack_surface_management_exception_handlers)


def test_attack_surface_management_container_import() -> None:
    from attack_surface_management.infrastructure.container import (
        AttackSurfaceManagementContainer,
    )

    assert callable(AttackSurfaceManagementContainer)
