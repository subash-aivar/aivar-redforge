from fastapi import APIRouter

from integration_hub.api.v1.discovery_routes import assets_router, discovery_router
from integration_hub.api.v1.routes import catalog_router
from integration_hub.api.v1.routes import router as connectors_router

router = APIRouter()
router.include_router(connectors_router)
router.include_router(catalog_router)
router.include_router(discovery_router)
router.include_router(assets_router)

__all__ = ["router"]
