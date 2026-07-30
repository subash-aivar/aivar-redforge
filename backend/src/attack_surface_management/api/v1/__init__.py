"""attack_surface_management API v1 routers."""

from fastapi import APIRouter

from attack_surface_management.api.v1.assets import assets_router
from attack_surface_management.api.v1.network_ranges import network_ranges_router

router = APIRouter()
router.include_router(
    assets_router,
    prefix="/attack-surface-management/assets",
    tags=["attack-surface-management"],
)
router.include_router(
    network_ranges_router,
    prefix="/attack-surface-management/network-ranges",
    tags=["attack-surface-management"],
)
