"""Operator API v1 routers."""

from fastapi import APIRouter

from red_team_operator.api.v1.operators import operators_router

router = APIRouter()
router.include_router(
    operators_router,
    prefix="/red-team-operators",
    tags=["red-team-operators"],
)
