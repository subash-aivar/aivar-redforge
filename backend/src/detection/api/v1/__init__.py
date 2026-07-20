"""Detection API v1 routers."""

from fastapi import APIRouter

from detection.api.v1.executions_findings import executions_router, findings_router
from detection.api.v1.phase4_routes import (
    correlate_finding_endpoint,
    coverage_router,
    evidence_router,
    exceptions_router,
    packs_router,
)
from detection.api.v1.platform_routes import platform_router
from detection.api.v1.rules import rules_router
from detection.api.v1.telemetry_sources import telemetry_router

# Register correlate on findings router BEFORE include_router copies routes.
findings_router.add_api_route(
    "/{finding_id}/correlate",
    correlate_finding_endpoint,
    methods=["POST"],
    response_model=None,
    tags=["detection-findings"],
)

router = APIRouter()
router.include_router(
    rules_router,
    prefix="/detection-rules",
    tags=["detection-rules"],
)
router.include_router(
    telemetry_router,
    prefix="/telemetry-sources",
    tags=["telemetry-sources"],
)
router.include_router(
    executions_router,
    prefix="/detection-executions",
    tags=["detection-executions"],
)
router.include_router(
    findings_router,
    prefix="/detection-findings",
    tags=["detection-findings"],
)
router.include_router(
    packs_router,
    prefix="/detection-packs",
    tags=["detection-packs"],
)
router.include_router(
    exceptions_router,
    prefix="/detection-exceptions",
    tags=["detection-exceptions"],
)
router.include_router(
    evidence_router,
    prefix="/detection-evidence",
    tags=["detection-evidence"],
)
router.include_router(
    coverage_router,
    prefix="/detection-coverage",
    tags=["detection-coverage"],
)
router.include_router(
    platform_router,
    prefix="/detection-platform",
    tags=["detection-platform"],
)
