"""risk_engine API v1 routers."""

from fastapi import APIRouter

from risk_engine.api.v1.risk_correlations import risk_correlations_router
from risk_engine.api.v1.risk_profiles import risk_profiles_router

router = APIRouter()
router.include_router(
    risk_profiles_router,
    prefix="/risk-profiles",
    tags=["risk-engine"],
)
router.include_router(
    risk_correlations_router,
    prefix="/risk-correlations",
    tags=["risk-engine"],
)
