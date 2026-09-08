"""intelligence_relationships API v1 routers."""

from fastapi import APIRouter

from intelligence_relationships.api.v1.relationships import relationships_router

router = APIRouter()
router.include_router(
    relationships_router, prefix="/relationships", tags=["intelligence-relationships"]
)
