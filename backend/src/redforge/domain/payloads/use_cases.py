"""Application use cases for the Prompt & Payload Engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from redforge.domain.payloads.entity import PayloadTemplate
from redforge.domain.payloads.exceptions import TemplateNotFoundError
from redforge.domain.payloads.value_objects import (
    RenderContext,
    RenderedPayload,
    TemplateType,
    TemplateVariable,
    VariableType,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from redforge.domain.payloads.events import PayloadEvent
    from redforge.domain.payloads.repository import PayloadTemplateRepository


@dataclass(frozen=True, slots=True)
class CreateTemplateCommand:
    """Input for creating a payload template."""

    name: str
    template_type: str
    body: str
    attack_id: str | None = None
    provider_hint: str = ""
    variables: list[dict[str, str]] | None = None


@dataclass(frozen=True, slots=True)
class RenderTemplateCommand:
    """Input for rendering a template."""

    template_id: str
    variables: dict[str, str]
    target_metadata: dict[str, str] | None = None
    attack_metadata: dict[str, str] | None = None


@dataclass(frozen=True, slots=True)
class TemplateResult:
    """Read-only representation of a PayloadTemplate."""

    id: str
    name: str
    template_type: str
    status: str
    version: str
    attack_id: str | None
    provider_hint: str
    is_renderable: bool
    variable_count: int
    created_at: str
    updated_at: str

    @classmethod
    def from_entity(cls, t: PayloadTemplate) -> TemplateResult:
        return cls(
            id=str(t.id),
            name=t.name,
            template_type=str(t.template_type),
            status=str(t.status),
            version=str(t.version),
            attack_id=t.attack_id,
            provider_hint=t.provider_hint,
            is_renderable=t.is_renderable,
            variable_count=len(t.variables),
            created_at=t.timestamps.created_at.isoformat(),
            updated_at=t.timestamps.updated_at.isoformat(),
        )


class CreateTemplateUseCase:
    """Create a new payload template."""

    def __init__(self, repository: PayloadTemplateRepository) -> None:
        self._repository = repository

    async def execute(
        self, command: CreateTemplateCommand
    ) -> tuple[TemplateResult, list[PayloadEvent]]:
        variables = [
            TemplateVariable(
                name=v.get("name", ""),
                variable_type=VariableType(v.get("type", "string")),
                required=v.get("required", "true") == "true",
                default_value=v.get("default", ""),
                description=v.get("description", ""),
            )
            for v in (command.variables or [])
        ]

        template = PayloadTemplate.create(
            name=command.name,
            template_type=TemplateType(command.template_type),
            body=command.body,
            variables=variables,
            attack_id=command.attack_id,
            provider_hint=command.provider_hint,
        )
        await self._repository.save(template)
        events = template.collect_events()
        return TemplateResult.from_entity(template), events


class PublishTemplateUseCase:
    """Publish a draft template."""

    def __init__(self, repository: PayloadTemplateRepository) -> None:
        self._repository = repository

    async def execute(
        self, template_id: str
    ) -> tuple[TemplateResult, list[PayloadEvent]]:
        entity_id = EntityId.from_string(template_id)
        template = await self._repository.get_by_id(entity_id)
        if template is None:
            raise TemplateNotFoundError(template_id)
        template.publish()
        await self._repository.save(template)
        events = template.collect_events()
        return TemplateResult.from_entity(template), events


class RenderTemplateUseCase:
    """Render a published template with context."""

    def __init__(self, repository: PayloadTemplateRepository) -> None:
        self._repository = repository

    async def execute(self, command: RenderTemplateCommand) -> RenderedPayload:
        entity_id = EntityId.from_string(command.template_id)
        template = await self._repository.get_by_id(entity_id)
        if template is None:
            raise TemplateNotFoundError(command.template_id)

        context = RenderContext(
            variables=command.variables,
            target_metadata=command.target_metadata or {},
            attack_metadata=command.attack_metadata or {},
        )
        return template.render(context)


class GetTemplateUseCase:
    """Retrieve a template by id."""

    def __init__(self, repository: PayloadTemplateRepository) -> None:
        self._repository = repository

    async def execute(self, template_id: str) -> TemplateResult:
        entity_id = EntityId.from_string(template_id)
        template = await self._repository.get_by_id(entity_id)
        if template is None:
            raise TemplateNotFoundError(template_id)
        return TemplateResult.from_entity(template)
