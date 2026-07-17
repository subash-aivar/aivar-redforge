"""Repository protocols for the Attack Path Engine — M22 Phase 5."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from redforge.domain.attack_path.entity import AttackPath
    from redforge.domain.attack_path.value_objects import AttackStep, PathConfidence, PathStatus


class AttackPathRepository(Protocol):
    async def get_by_id(
        self, path_id: str, *, organization_id: str
    ) -> AttackPath | None: ...

    async def add(self, path: AttackPath) -> AttackPath: ...

    async def update(self, path: AttackPath) -> AttackPath: ...

    async def list_for_organization(
        self,
        organization_id: str,
        *,
        status: PathStatus | None = None,
        root_technique_id: str | None = None,
        confidence_floor: PathConfidence | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AttackPath]: ...

    async def list_by_root_entity(
        self,
        organization_id: str,
        root_entity_id: str,
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AttackPath]: ...


class AttackPathStepRepository(Protocol):
    async def replace_steps(
        self, path_id: str, organization_id: str, steps: list[AttackStep]
    ) -> None: ...

    async def list_steps(
        self, path_id: str, *, organization_id: str
    ) -> list[AttackStep]: ...
