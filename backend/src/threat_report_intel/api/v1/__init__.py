"""threat_report_intel API v1 routers."""

from fastapi import APIRouter

from threat_report_intel.api.v1.threat_reports import threat_report_router

router = APIRouter()
router.include_router(
    threat_report_router, prefix="/threat-report-intel", tags=["threat-report-intel"]
)
