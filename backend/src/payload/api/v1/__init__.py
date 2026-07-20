"""Payload API v1 routers."""

from fastapi import APIRouter

from payload.api.v1.routes import payloads_router, plugins_router

router = APIRouter()
router.include_router(payloads_router, tags=["red-team-payloads"])
router.include_router(
    plugins_router,
    prefix="/plugins",
    tags=["payload-plugins"],
)
