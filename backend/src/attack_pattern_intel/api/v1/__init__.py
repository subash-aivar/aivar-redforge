"""attack_pattern_intel API v1 routers."""

from fastapi import APIRouter

from attack_pattern_intel.api.v1.attack_patterns import attack_patterns_router

router = APIRouter()
router.include_router(
    attack_patterns_router, prefix="/attack-patterns", tags=["attack-pattern-intel"]
)
