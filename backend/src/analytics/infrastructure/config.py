"""Analytics feature flags / configuration (Phase 5)."""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AnalyticsSettings:
    enable_ml_anomaly: bool = True
    enable_graph_anomaly_writes: bool = True
    enable_iqr_rolling: bool = True
    projection_max_retries: int = 3
    kpi_dashboard_soft_sla_ms: float = 50.0

    @classmethod
    def from_env(cls) -> AnalyticsSettings:
        return cls(
            enable_ml_anomaly=os.getenv("M33_ENABLE_ML_ANOMALY", "1") != "0",
            enable_graph_anomaly_writes=os.getenv("M33_ENABLE_GRAPH_ANOMALY", "1") != "0",
            enable_iqr_rolling=os.getenv("M33_ENABLE_IQR_ROLLING", "1") != "0",
            projection_max_retries=int(os.getenv("M33_PROJECTION_MAX_RETRIES", "3")),
            kpi_dashboard_soft_sla_ms=float(os.getenv("M33_KPI_SLA_MS", "50")),
        )
