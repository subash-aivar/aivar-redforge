"""Root API router that aggregates all versioned routers.

New API versions are added here as additional router includes.
Existing versions remain stable and unchanged.
"""

from fastapi import APIRouter

from redforge.api.v1 import build_v1_router
from redforge.api.v1 import router as v1_router
from redforge.core.config import ProductEdition


def build_root_router(edition: ProductEdition = "full") -> APIRouter:
    """Mounts `build_v1_router(edition)` at /api/v1 — the one place the
    edition-aware v1 router reaches the app (ADR-0009)."""
    root = APIRouter()
    root.include_router(build_v1_router(edition), prefix="/api/v1")
    return root


# Backward-compatible module-level symbol — identical to the router this
# module has always exported ("full" edition, i.e. every route).
root_router = build_root_router("full")

__all__ = ["build_root_router", "root_router", "v1_router"]
