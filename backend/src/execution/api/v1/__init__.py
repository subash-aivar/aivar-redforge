"""Execution API v1 routers."""

from fastapi import APIRouter

from execution.api.v1.attack_actions import attack_actions_router
from execution.api.v1.execution_workers import workers_router
from execution.api.v1.journals import journals_router
from execution.api.v1.kill_switches import kill_switches_router
from execution.api.v1.projections import projections_router

router = APIRouter()
router.include_router(
    kill_switches_router,
    prefix="/kill-switches",
    tags=["kill-switches"],
)
router.include_router(
    journals_router,
    prefix="/execution-journals",
    tags=["execution-journals"],
)
router.include_router(
    attack_actions_router,
    prefix="/attack-actions",
    tags=["attack-actions"],
)
router.include_router(
    workers_router,
    prefix="/execution-workers",
    tags=["execution-workers"],
)
router.include_router(
    projections_router,
    prefix="/red-team-projections",
    tags=["red-team-projections"],
)
