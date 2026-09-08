"""infrastructure_intel API v1 routers."""

from fastapi import APIRouter

from infrastructure_intel.api.v1.infrastructure import infrastructure_router

router = APIRouter()
router.include_router(
    infrastructure_router, prefix="/infrastructure-intel", tags=["infrastructure-intel"]
)
