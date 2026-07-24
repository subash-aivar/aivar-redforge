"""AiTargetApplicationService — a thin application service wiring
`RegisterAiTargetCommand` to `AiTarget` aggregate construction and the
injected `IAiTargetRegistry` (M47A). No business logic beyond what the
aggregate already encapsulates — this service never scans prompts,
never evaluates guardrails, never scores risk. Holds no state beyond
its injected collaborator, so it stays stateless (the registry is the
framework's only stateful component)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ai_security.application.dtos.ai_target_dto import AiTargetDTO
from ai_security.application.exceptions import AiTargetNotFoundError
from ai_security.application.services.command_validation import validate_name
from ai_security.domain.aggregates.ai_target import AiTarget
from ai_security.domain.value_objects.identifiers import TargetId

if TYPE_CHECKING:
    from ai_security.application.commands.ai_target_commands import RegisterAiTargetCommand
    from ai_security.application.ports.i_ai_target_registry import IAiTargetRegistry
    from ai_security.application.queries.ai_target_queries import (
        GetAiTargetQuery,
        ListAiTargetsQuery,
    )
    from ai_security.domain.value_objects.identifiers import TenantId


def _to_dto(target: AiTarget) -> AiTargetDTO:
    return AiTargetDTO(
        target_id=str(target.target_id),
        tenant_id=str(target.tenant_id),
        name=target.name,
        target_type=str(target.target_type),
        registered_at=target.registered_at,
    )


class AiTargetApplicationService:
    def __init__(self, registry: IAiTargetRegistry) -> None:
        self._registry = registry

    # -- commands ------------------------------------------------------

    def register_target(self, cmd: RegisterAiTargetCommand) -> AiTargetDTO:
        validate_name(cmd.name)
        now = datetime.now(UTC)
        target = AiTarget.register(
            target_id=TargetId.generate(),
            tenant_id=cmd.tenant_id,
            name=cmd.name,
            target_type=cmd.target_type,
            now=now,
        )
        self._registry.register(target)
        return _to_dto(target)

    def _require_target(self, tenant_id: TenantId, target_id: TargetId) -> AiTarget:
        target = self._registry.get(tenant_id, target_id)
        if target is None:
            raise AiTargetNotFoundError(target_id)
        return target

    # -- queries ---------------------------------------------------------

    def get_target(self, query: GetAiTargetQuery) -> AiTargetDTO | None:
        target = self._registry.get(query.tenant_id, query.target_id)
        return _to_dto(target) if target is not None else None

    def list_targets(self, query: ListAiTargetsQuery) -> tuple[AiTargetDTO, ...]:
        return tuple(_to_dto(t) for t in self._registry.list(query.tenant_id))
