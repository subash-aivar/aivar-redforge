"""Application service for Validation Policy use cases."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from redforge.application.contracts import UnitOfWorkFactory
from redforge.core.exceptions import NotFoundError
from redforge.shared.identifiers import EntityId


@dataclass(frozen=True, slots=True)
class PolicyDTO:
    """Application-layer representation of a Validation Policy."""

    id: str
    organization_id: str
    name: str
    description: str
    attack_ids: list[str]
    schedule_cron: str | None
    enabled: bool
    status: str
    created_at: str = ""
    updated_at: str = ""


class PolicyService:
    """Orchestrates Validation Policy use cases via UnitOfWork."""

    def __init__(self, uow_factory: UnitOfWorkFactory) -> None:
        self._uow_factory = uow_factory

    async def create(
        self, organization_id: str, name: str, description: str,
        attack_ids: list[str], schedule_cron: str | None, enabled: bool,
    ) -> PolicyDTO:
        now = datetime.now(UTC).isoformat()
        policy_id = str(EntityId.generate())
        data: dict[str, Any] = {
            "id": policy_id, "organization_id": organization_id,
            "name": name, "description": description,
            "attack_ids": attack_ids, "schedule_cron": schedule_cron,
            "enabled": enabled, "status": "active",
            "created_at": now, "updated_at": now,
        }
        async with self._uow_factory() as uow:
            await uow.policies.save(data)
            await uow.commit()
        return PolicyDTO(**data)

    async def get_by_id(self, policy_id: str, organization_id: str) -> PolicyDTO:
        """Retrieve a Policy by ID, scoped to the caller's organization."""
        async with self._uow_factory() as uow:
            data = await uow.policies.get_by_id_for_organization(
                policy_id, organization_id,
            )
        if data is None:
            raise NotFoundError("ValidationPolicy", policy_id)
        return PolicyDTO(**data)

    async def list_policies(
        self, organization_id: str, enabled: bool | None,
        limit: int, offset: int,
    ) -> list[PolicyDTO]:
        async with self._uow_factory() as uow:
            items = await uow.policies.list_by_organization(
                organization_id, enabled, limit, offset,
            )
        return [PolicyDTO(**d) for d in items]

    async def update(
        self, policy_id: str, organization_id: str, updates: dict[str, Any]
    ) -> PolicyDTO:
        """Update a Policy, scoped to the caller's organization."""
        async with self._uow_factory() as uow:
            updated = await uow.policies.update_for_organization(
                policy_id, organization_id, updates,
            )
            if updated is None:
                raise NotFoundError("ValidationPolicy", policy_id)
            await uow.commit()
        return PolicyDTO(**updated)

    async def delete(self, policy_id: str, organization_id: str) -> None:
        """Delete a Policy, scoped to the caller's organization."""
        async with self._uow_factory() as uow:
            deleted = await uow.policies.delete_for_organization(
                policy_id, organization_id,
            )
            if not deleted:
                raise NotFoundError("ValidationPolicy", policy_id)
            await uow.commit()
