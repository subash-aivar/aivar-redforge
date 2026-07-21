"""Production configuration for exposure_reporting (Phase 5)."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExposureReportingSettings:
    schema_name: str = "exposure_reporting"
    max_report_assets: int = 1000
    trend_retention_points: int = 365
    enable_graph_projection: bool = True
    enable_background_workers: bool = True
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> ExposureReportingSettings:
        return cls(
            schema_name=os.getenv("EXPOSURE_REPORTING_SCHEMA", "exposure_reporting"),
            max_report_assets=int(os.getenv("EXPOSURE_REPORTING_MAX_ASSETS", "1000")),
            trend_retention_points=int(os.getenv("EXPOSURE_REPORTING_TREND_RETENTION", "365")),
            enable_graph_projection=os.getenv("EXPOSURE_REPORTING_GRAPH_ENABLED", "true").lower()
            in {"1", "true", "yes"},
            enable_background_workers=os.getenv(
                "EXPOSURE_REPORTING_WORKERS_ENABLED", "true"
            ).lower()
            in {"1", "true", "yes"},
            log_level=os.getenv("EXPOSURE_REPORTING_LOG_LEVEL", "INFO"),
        )
