from __future__ import annotations

import pytest

from analytics.domain.exceptions.domain_exceptions import AnalyticsQueryValidationError
from analytics.domain.services.analytics_query_validation_service import (
    AnalyticsQueryValidationService,
)


def test_rejects_non_analytics_schema() -> None:
    svc = AnalyticsQueryValidationService()
    with pytest.raises(AnalyticsQueryValidationError):
        svc.validate_template("SELECT * FROM public.users WHERE tenant_id = :tenant_id")


def test_requires_tenant_id_placeholder() -> None:
    svc = AnalyticsQueryValidationService()
    with pytest.raises(AnalyticsQueryValidationError):
        svc.validate_template("SELECT * FROM analytics.kpi_snapshots")


def test_accepts_whitelisted_template() -> None:
    svc = AnalyticsQueryValidationService()
    svc.validate_template("SELECT * FROM analytics.kpi_snapshots WHERE tenant_id = :tenant_id")


def test_rejects_string_format_injection_markers() -> None:
    svc = AnalyticsQueryValidationService()
    with pytest.raises(AnalyticsQueryValidationError):
        svc.validate_template("SELECT * FROM analytics.kpi_snapshots WHERE tenant_id = '%s'")
