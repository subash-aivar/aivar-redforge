"""Engagement API v1 routers."""

from fastapi import APIRouter

from engagement.api.v1.routes import engagements_router, target_authorizations_router

router = APIRouter()
router.include_router(
    engagements_router,
    prefix="/engagements",
    tags=["engagements"],
)
router.include_router(
    target_authorizations_router,
    prefix="/target-authorizations",
    tags=["target-authorizations"],
)
