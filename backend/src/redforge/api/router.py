"""Root API router that aggregates all versioned routers.

New API versions are added here as additional router includes.
Existing versions remain stable and unchanged.
"""

from fastapi import APIRouter

from redforge.api.v1 import router as v1_router

root_router = APIRouter()
root_router.include_router(v1_router, prefix="/api/v1")
