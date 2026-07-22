from fastapi import APIRouter

from integration_hub.api.v1.routes import catalog_router
from integration_hub.api.v1.routes import router as connectors_router

router = APIRouter()
router.include_router(connectors_router)
router.include_router(catalog_router)

__all__ = ["router"]
