"""campaign_intel API v1 routers."""

from fastapi import APIRouter

from campaign_intel.api.v1.campaigns import campaign_router

router = APIRouter()
router.include_router(campaign_router, prefix="/campaign-intel", tags=["campaign-intel"])
