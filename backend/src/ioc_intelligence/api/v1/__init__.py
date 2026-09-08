"""ioc_intelligence API v1 routers."""

from fastapi import APIRouter

from ioc_intelligence.api.v1.iocs import iocs_router

router = APIRouter()
router.include_router(iocs_router, prefix="/iocs", tags=["ioc-intelligence"])
