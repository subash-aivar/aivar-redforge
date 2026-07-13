"""Application service for Attack Library use cases."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from redforge.application.contracts import UnitOfWorkFactory
from redforge.core.exceptions import NotFoundError
from redforge.shared.identifiers import EntityId


@dataclass(frozen=True, slots=True)
class AttackDTO:
    """Application-layer representation of an Attack Definition."""

    id: str
    name: str
    display_name: str
    description: str
    category: str
    technique: str
    severity: str
    status: str
    version: str
    tags: list[str] = field(default_factory=list)
    created_at: str = ""
    updated_at: str = ""


class AttackLibraryService:
    """Orchestrates Attack Library use cases via UnitOfWork."""

    def __init__(self, uow_factory: UnitOfWorkFactory) -> None:
        self._uow_factory = uow_factory

    async def create(
        self, name: str, display_name: str, description: str,
        category: str, technique: str, severity: str,
    ) -> AttackDTO:
        now = datetime.now(UTC).isoformat()
        attack_id = str(EntityId.generate())
        data: dict[str, Any] = {
            "id": attack_id, "name": name, "display_name": display_name,
            "description": description, "category": category,
            "technique": technique, "severity": severity,
            "status": "draft", "version": "1.0.0", "tags": [],
            "created_at": now, "updated_at": now,
        }
        async with self._uow_factory() as uow:
            await uow.attacks.save(data)
            await uow.commit()
        return AttackDTO(**data)

    async def get_by_id(self, attack_id: str) -> AttackDTO:
        async with self._uow_factory() as uow:
            data = await uow.attacks.get_by_id(attack_id)
        if data is None:
            raise NotFoundError("AttackDefinition", attack_id)
        return AttackDTO(**data)

    async def list_attacks(
        self, category: str | None, severity: str | None,
        status: str | None, limit: int, offset: int,
    ) -> list[AttackDTO]:
        async with self._uow_factory() as uow:
            items = await uow.attacks.list_all(category, severity, status, limit, offset)
        return [AttackDTO(**d) for d in items]

    async def publish(self, attack_id: str) -> AttackDTO:
        async with self._uow_factory() as uow:
            updated = await uow.attacks.update_status(attack_id, "published")
            if updated is None:
                raise NotFoundError("AttackDefinition", attack_id)
            await uow.commit()
        return AttackDTO(**updated)

    async def deprecate(self, attack_id: str) -> AttackDTO:
        async with self._uow_factory() as uow:
            updated = await uow.attacks.update_status(attack_id, "deprecated")
            if updated is None:
                raise NotFoundError("AttackDefinition", attack_id)
            await uow.commit()
        return AttackDTO(**updated)
