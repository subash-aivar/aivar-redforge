"""threat_actor_intel API v1 routers."""

from fastapi import APIRouter

from threat_actor_intel.api.v1.threat_actors import threat_actors_router

router = APIRouter()
router.include_router(
    threat_actors_router,
    prefix="/threat-actors",
    tags=["threat-actor-intel"],
)
