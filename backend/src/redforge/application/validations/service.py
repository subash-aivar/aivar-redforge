"""Application service for Validation Run use cases."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from redforge.application.contracts import UnitOfWorkFactory
from redforge.core.exceptions import NotFoundError
from redforge.shared.identifiers import EntityId


@dataclass(frozen=True, slots=True)
class ValidationRunDTO:
    """Application-layer representation of a ValidationRun."""

    id: str
    organization_id: str
    target_id: str
    status: str
    trigger_type: str
    policy_id: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    summary: dict[str, Any] | None = None
    created_at: str = ""
    updated_at: str = ""


class ValidationRunService:
    """Orchestrates Validation Run CRUD/lifecycle use cases (schedule, cancel,
    list, get). This is NOT the execution pipeline — it never runs attacks.

    For the canonical end-to-end AI security validation pipeline (attack
    resolution → execution → evaluation → evidence/findings → persistence),
    see application/validation_service.py::ValidationService. The two are
    named to avoid ambiguity: this one is a thin CRUD layer over
    ValidationRun records; that one is the production execution engine.

    Receives a UnitOfWork factory. Each operation opens a UoW,
    performs work through repositories, and commits atomically.
    """

    def __init__(self, uow_factory: UnitOfWorkFactory) -> None:
        self._uow_factory = uow_factory

    async def schedule(
        self, organization_id: str, target_id: str,
        trigger_type: str, policy_id: str | None,
    ) -> ValidationRunDTO:
        now = datetime.now(UTC).isoformat()
        run_id = str(EntityId.generate())
        data: dict[str, Any] = {
            "id": run_id, "organization_id": organization_id,
            "target_id": target_id, "status": "scheduled",
            "trigger_type": trigger_type, "policy_id": policy_id,
            "created_at": now, "updated_at": now,
        }
        async with self._uow_factory() as uow:
            await uow.validations.save(data)
            await uow.commit()
        return ValidationRunDTO(**data)

    async def get_by_id(self, run_id: str, organization_id: str) -> ValidationRunDTO:
        """Retrieve a ValidationRun by ID, scoped to the caller's organization."""
        async with self._uow_factory() as uow:
            data = await uow.validations.get_by_id_for_organization(
                run_id, organization_id,
            )
        if data is None:
            raise NotFoundError("ValidationRun", run_id)
        return ValidationRunDTO(**data)

    async def list_runs(
        self, organization_id: str, target_id: str | None,
        status: str | None, limit: int, offset: int,
    ) -> list[ValidationRunDTO]:
        async with self._uow_factory() as uow:
            items = await uow.validations.list_by_organization(
                organization_id, target_id, status, limit, offset,
            )
        return [ValidationRunDTO(**d) for d in items]

    async def cancel(self, run_id: str, organization_id: str) -> ValidationRunDTO:
        """Cancel a ValidationRun, scoped to the caller's organization."""
        async with self._uow_factory() as uow:
            data = await uow.validations.get_by_id_for_organization(
                run_id, organization_id,
            )
            if data is None:
                raise NotFoundError("ValidationRun", run_id)
            data["status"] = "cancelled"
            await uow.validations.save(data)
            await uow.commit()
        return ValidationRunDTO(**data)
