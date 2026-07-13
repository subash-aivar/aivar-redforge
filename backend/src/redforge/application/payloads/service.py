"""Application service for Payload Template use cases."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from redforge.application.contracts import UnitOfWorkFactory
from redforge.core.exceptions import NotFoundError
from redforge.shared.identifiers import EntityId


@dataclass(frozen=True, slots=True)
class PayloadTemplateDTO:
    """Application-layer representation of a PayloadTemplate."""

    id: str
    name: str
    description: str
    category: str
    template: str
    variables: list[str]
    severity: str
    status: str
    created_at: str = ""
    updated_at: str = ""


class PayloadTemplateService:
    """Orchestrates Payload Template use cases via UnitOfWork."""

    def __init__(self, uow_factory: UnitOfWorkFactory) -> None:
        self._uow_factory = uow_factory

    async def create(
        self, name: str, description: str, category: str,
        template: str, variables: list[str], severity: str,
    ) -> PayloadTemplateDTO:
        now = datetime.now(UTC).isoformat()
        template_id = str(EntityId.generate())
        data: dict[str, Any] = {
            "id": template_id, "name": name, "description": description,
            "category": category, "template": template,
            "variables": variables, "severity": severity,
            "status": "active", "created_at": now, "updated_at": now,
        }
        async with self._uow_factory() as uow:
            await uow.payloads.save(data)
            await uow.commit()
        return PayloadTemplateDTO(**data)

    async def get_by_id(self, template_id: str) -> PayloadTemplateDTO:
        async with self._uow_factory() as uow:
            data = await uow.payloads.get_by_id(template_id)
        if data is None:
            raise NotFoundError("PayloadTemplate", template_id)
        return PayloadTemplateDTO(**data)

    async def list_templates(
        self, category: str | None, severity: str | None,
        limit: int, offset: int,
    ) -> list[PayloadTemplateDTO]:
        async with self._uow_factory() as uow:
            items = await uow.payloads.list_all(category, severity, limit, offset)
        return [PayloadTemplateDTO(**d) for d in items]

    async def delete(self, template_id: str) -> None:
        async with self._uow_factory() as uow:
            await uow.payloads.delete(template_id)
            await uow.commit()
