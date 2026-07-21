"""Canonical enums for ml_pipeline BC (M33 Finalization §2 / C2)."""

from __future__ import annotations

from enum import StrEnum


class MLModelType(StrEnum):
    ANOMALY_DETECTOR = "ANOMALY_DETECTOR"
    RISK_PREDICTOR = "RISK_PREDICTOR"
    COVERAGE_FORECASTER = "COVERAGE_FORECASTER"


class MLAlgorithm(StrEnum):
    ISOLATION_FOREST = "ISOLATION_FOREST"
    RANDOM_FOREST = "RANDOM_FOREST"
    LINEAR_REGRESSION = "LINEAR_REGRESSION"


class MLModelStatus(StrEnum):
    TRAINING = "TRAINING"
    TRAINED = "TRAINED"
    DEPLOYED = "DEPLOYED"
    DEPRECATED = "DEPRECATED"
    FAILED = "FAILED"


class AnalyticsRole(StrEnum):
    """Canonical analytics RBAC (local copy — no analytics.domain import)."""

    VIEWER = "analytics:viewer"
    ANALYST = "analytics:analyst"
    ENGINEER = "analytics:engineer"
    ADMIN = "analytics:admin"


# Accuracy gates (frozen M33 C2). Fail → MLModelStatus.FAILED.
# ANOMALY_DETECTOR (IsolationForest): AUC-PR >= 0.65
# RISK_PREDICTOR (RandomForest): AUC-ROC >= 0.70
# COVERAGE_FORECASTER (LinearRegression): R² >= 0.50
ACCURACY_THRESHOLDS: dict[MLModelType, tuple[str, float]] = {
    MLModelType.ANOMALY_DETECTOR: ("auc_pr", 0.65),
    MLModelType.RISK_PREDICTOR: ("auc_roc", 0.70),
    MLModelType.COVERAGE_FORECASTER: ("r2", 0.50),
}

SIGNAL_TTL_DAYS = 30
PSI_MODERATE = 0.10
PSI_SEVERE = 0.20
