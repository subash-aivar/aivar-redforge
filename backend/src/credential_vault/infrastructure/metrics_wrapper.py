"""Thin instrumentation wrappers for application services."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

from credential_vault.infrastructure import metrics

if TYPE_CHECKING:
    from credential_vault.application.services.credential_application_service import (
        CredentialApplicationService,
    )


class MetricsCredentialApplicationService:
    """Delegates to CredentialApplicationService and records Prometheus metrics."""

    def __init__(self, inner: CredentialApplicationService) -> None:
        self._inner = inner

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def create_credential(self, cmd: Any) -> Any:
        return await self._record(
            "create_credential", str(cmd.tenant_id), self._inner.create_credential(cmd)
        )

    async def resolve_credential(self, cmd: Any) -> Any:
        return await self._record(
            "resolve_credential", str(cmd.tenant_id), self._inner.resolve_credential(cmd)
        )

    async def rotate_credential(self, cmd: Any) -> Any:
        return await self._record(
            "rotate_credential", str(cmd.tenant_id), self._inner.rotate_credential(cmd)
        )

    async def _record(self, operation: str, tenant_id: str, coro: Any) -> Any:
        start = time.perf_counter()
        try:
            result = await coro
            metrics.credential_operations_total.labels(
                operation=operation, outcome="success", tenant_id=tenant_id
            ).inc()
            return result
        except Exception:
            metrics.credential_operations_total.labels(
                operation=operation, outcome="failure", tenant_id=tenant_id
            ).inc()
            raise
        finally:
            metrics.credential_encryption_duration.labels(operation=operation).observe(
                time.perf_counter() - start
            )
