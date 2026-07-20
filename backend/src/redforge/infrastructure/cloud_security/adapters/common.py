"""Shared helpers and credential material for cloud provider adapters."""

from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class CredentialMaterial:
    """Resolved credential fields for adapter client construction (never logged)."""

    access_key_id: str | None = None
    secret_access_key: str | None = None
    session_token: str | None = None
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    subscription_id: str | None = None
    project_id: str | None = None
    service_account_json: str | None = None
    regions: tuple[str, ...] = ()


class AwsSessionFactory(Protocol):
    """Builds a boto3-compatible session from credential material."""

    def __call__(self, material: CredentialMaterial, *, region: str | None = None) -> object: ...


class CloudAdapterDependencyError(RuntimeError):
    """Raised when an optional cloud SDK package is not installed."""


async def empty_async_iterator() -> AsyncIterator[Any]:
    """Async generator that yields nothing (Phase 2 out-of-scope adapter methods)."""
    if False:  # pragma: no cover
        yield None
    return
