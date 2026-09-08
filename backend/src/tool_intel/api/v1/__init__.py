"""tool_intel API v1 routers."""

from fastapi import APIRouter

from tool_intel.api.v1.tools import tool_router

router = APIRouter()
router.include_router(tool_router, prefix="/tool-intel", tags=["tool-intel"])
