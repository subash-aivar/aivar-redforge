"""Evidence API v1 routers."""

from fastapi import APIRouter

from evidence.api.v1.routes import chains_router, evidence_router

router = APIRouter()
router.include_router(evidence_router, tags=["red-team-evidence"])
router.include_router(
    chains_router,
    prefix="/chains",
    tags=["evidence-chains"],
)
