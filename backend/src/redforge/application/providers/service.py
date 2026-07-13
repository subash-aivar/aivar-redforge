"""Application service for Provider use cases.

Tenant ownership (M2): every provider configuration is scoped to the
organization that created it. `organization_id` is required at
registration and enforced on every read/mutation — a request from a
different tenant for a provider it does not own is treated identically
to the provider not existing (NotFoundError, not a 403) so tenant B can
never even confirm tenant A's provider_id is valid.

Legacy pre-M2 rows (registered before organization ownership existed)
have `organization_id = None` in their stored data. These are treated as
NOT OWNED BY ANY TENANT and are excluded from every tenant-scoped
query/mutation — they are not silently assigned to any organization,
and are not usable for campaign launch by any tenant, until an explicit
future reconciliation capability assigns them. This is a deliberate,
documented gap (see M2 report), not an oversight.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from redforge.application.contracts import UnitOfWorkFactory
from redforge.core.exceptions import NotFoundError
from redforge.shared.identifiers import EntityId


@dataclass(frozen=True, slots=True)
class ProviderDTO:
    """Application-layer representation of a Provider.

    auth_ref is an environment variable NAME (e.g. 'OPENAI_API_KEY').
    It is safe to include in DTOs and API responses — it carries no secret.
    The resolved credential is never part of this DTO.

    organization_id is None only for legacy pre-M2 rows requiring
    reconciliation (see module docstring) — every provider registered
    under M2 always has a non-None organization_id.
    """

    id: str
    name: str
    provider_type: str
    base_url: str
    models: list[str]
    enabled: bool
    status: str
    organization_id: str | None = None
    auth_ref: str = ""
    created_at: str = ""
    updated_at: str = ""


class ProviderService:
    """Orchestrates Provider use cases via UnitOfWork."""

    def __init__(self, uow_factory: UnitOfWorkFactory) -> None:
        self._uow_factory = uow_factory

    async def register(
        self, organization_id: str, name: str, provider_type: str, base_url: str,
        models: list[str], enabled: bool, auth_ref: str = "",
    ) -> ProviderDTO:
        now = datetime.now(UTC).isoformat()
        provider_id = str(EntityId.generate())
        data: dict[str, Any] = {
            "id": provider_id, "organization_id": organization_id, "name": name,
            "provider_type": provider_type, "base_url": base_url,
            "models": models, "enabled": enabled, "status": "active",
            "auth_ref": auth_ref,
            "created_at": now, "updated_at": now,
        }
        async with self._uow_factory() as uow:
            await uow.providers.save(data)
            await uow.commit()
        return ProviderDTO(**data)

    async def get_by_id(self, provider_id: str, organization_id: str) -> ProviderDTO:
        """Raises NotFoundError for a provider owned by a different
        organization, identically to a nonexistent provider_id — a
        cross-tenant caller cannot distinguish "not yours" from "doesn't
        exist."
        """
        async with self._uow_factory() as uow:
            data = await uow.providers.get_by_id(provider_id)
        if data is None or data.get("organization_id") != organization_id:
            raise NotFoundError("Provider", provider_id)
        return self._dto_from_data(data)

    async def list_providers(
        self, organization_id: str, provider_type: str | None, enabled: bool | None,
        limit: int, offset: int,
    ) -> list[ProviderDTO]:
        async with self._uow_factory() as uow:
            items = await uow.providers.list_all(provider_type, enabled, limit, offset)
        # Filtered in the application layer (the document-store repository
        # doesn't support a JSON-field WHERE clause for organization_id
        # without a schema change to the document store itself) — every
        # row not owned by the caller's organization (including legacy
        # organization_id=None rows) is excluded here, never returned.
        owned = [d for d in items if d.get("organization_id") == organization_id]
        return [self._dto_from_data(d) for d in owned]

    async def disable(self, provider_id: str, organization_id: str) -> ProviderDTO:
        async with self._uow_factory() as uow:
            existing = await uow.providers.get_by_id(provider_id)
            if existing is None or existing.get("organization_id") != organization_id:
                raise NotFoundError("Provider", provider_id)
            updated = await uow.providers.update(
                provider_id, {"enabled": False, "status": "disabled"},
            )
            if updated is None:
                raise NotFoundError("Provider", provider_id)
            await uow.commit()
        return self._dto_from_data(updated)

    async def enable(self, provider_id: str, organization_id: str) -> ProviderDTO:
        async with self._uow_factory() as uow:
            existing = await uow.providers.get_by_id(provider_id)
            if existing is None or existing.get("organization_id") != organization_id:
                raise NotFoundError("Provider", provider_id)
            updated = await uow.providers.update(
                provider_id, {"enabled": True, "status": "active"},
            )
            if updated is None:
                raise NotFoundError("Provider", provider_id)
            await uow.commit()
        return self._dto_from_data(updated)

    @staticmethod
    def _dto_from_data(data: dict[str, Any]) -> ProviderDTO:
        """Build a ProviderDTO from a persisted data dict.

        Older records pre-dating the auth_ref/organization_id fields will
        have them absent — default to "" / None (unconfigured / unowned).
        """
        return ProviderDTO(
            id=data["id"],
            name=data["name"],
            provider_type=data["provider_type"],
            base_url=data.get("base_url", ""),
            models=data.get("models", []),
            enabled=data.get("enabled", True),
            status=data.get("status", "active"),
            organization_id=data.get("organization_id"),
            auth_ref=data.get("auth_ref", ""),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )
