"""Operation API v1 routers."""

from fastapi import APIRouter

from operation.api.v1.operations import operations_router
from operation.api.v1.plan_versions import plan_versions_router

router = APIRouter()
router.include_router(
    operations_router,
    prefix="/operations",
    tags=["operations"],
)
router.include_router(
    plan_versions_router,
    prefix="/execution-plan-versions",
    tags=["execution-plan-versions"],
)
