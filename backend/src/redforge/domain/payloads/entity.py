"""PayloadTemplate aggregate root.

A PayloadTemplate defines the structure of an executable payload.
Attack definitions reference templates. The execution engine renders
templates with context to produce payloads dispatched to providers.

One attack may have many templates (different providers/formats).
"""

import re
from typing import Self

from redforge.domain.payloads.events import (
    PayloadEvent,
    TemplateArchived,
    TemplateCreated,
    TemplatePublished,
    _now,
)
from redforge.domain.payloads.exceptions import (
    InvalidTemplateTransitionError,
    TemplateArchivedError,
    TemplateRenderError,
)
from redforge.domain.payloads.value_objects import (
    RenderContext,
    RenderedPayload,
    TemplateStatus,
    TemplateType,
    TemplateVariable,
    TemplateVersion,
)
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import AuditTimestamps

_VAR_PATTERN = re.compile(r"\{\{\s*(\w+)\s*\}\}")


class PayloadTemplate:
    """Payload Template aggregate root.

    Invariants:
    - Always has a name, type, and content body.
    - Variables declared must exist in the content body.
    - Only PUBLISHED templates can be rendered.
    - Archived templates are immutable.
    - Rendering validates all required variables are provided.
    """

    __slots__ = (
        "_attack_id",
        "_body",
        "_events",
        "_id",
        "_metadata",
        "_name",
        "_provider_hint",
        "_status",
        "_tags",
        "_template_type",
        "_timestamps",
        "_variables",
        "_version",
    )

    def __init__(
        self,
        id: EntityId,
        name: str,
        template_type: TemplateType,
        body: str,
        variables: list[TemplateVariable],
        attack_id: str | None,
        provider_hint: str,
        version: TemplateVersion,
        status: TemplateStatus,
        tags: set[str],
        metadata: dict[str, str],
        timestamps: AuditTimestamps,
    ) -> None:
        self._id = id
        self._name = name
        self._template_type = template_type
        self._body = body
        self._variables = variables
        self._attack_id = attack_id
        self._provider_hint = provider_hint
        self._version = version
        self._status = status
        self._tags = tags
        self._metadata = metadata
        self._timestamps = timestamps
        self._events: list[PayloadEvent] = []

    @classmethod
    def create(
        cls,
        name: str,
        template_type: TemplateType,
        body: str,
        variables: list[TemplateVariable] | None = None,
        attack_id: str | None = None,
        provider_hint: str = "",
    ) -> Self:
        """Create a new payload template in DRAFT status."""
        if not name or len(name.strip()) < 3:
            raise ValueError("Template name must be at least 3 characters")
        if not body.strip():
            raise ValueError("Template body must not be empty")

        template = cls(
            id=EntityId.generate(),
            name=name.strip(),
            template_type=template_type,
            body=body,
            variables=list(variables or []),
            attack_id=attack_id,
            provider_hint=provider_hint,
            version=TemplateVersion.initial(),
            status=TemplateStatus.DRAFT,
            tags=set(),
            metadata={},
            timestamps=AuditTimestamps.create(),
        )
        template._record_event(
            TemplateCreated(
                occurred_at=_now(),
                template_id=str(template._id),
                name=template._name,
                template_type=str(template_type),
            )
        )
        return template

    # ─── Properties ───────────────────────────────────────────────────────

    @property
    def id(self) -> EntityId:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def template_type(self) -> TemplateType:
        return self._template_type

    @property
    def body(self) -> str:
        return self._body

    @property
    def variables(self) -> tuple[TemplateVariable, ...]:
        return tuple(self._variables)

    @property
    def attack_id(self) -> str | None:
        return self._attack_id

    @property
    def provider_hint(self) -> str:
        return self._provider_hint

    @property
    def version(self) -> TemplateVersion:
        return self._version

    @property
    def status(self) -> TemplateStatus:
        return self._status

    @property
    def tags(self) -> frozenset[str]:
        return frozenset(self._tags)

    @property
    def metadata(self) -> dict[str, str]:
        return dict(self._metadata)

    @property
    def timestamps(self) -> AuditTimestamps:
        return self._timestamps

    @property
    def is_renderable(self) -> bool:
        return self._status == TemplateStatus.PUBLISHED

    # ─── Lifecycle ────────────────────────────────────────────────────────

    def publish(self) -> None:
        """Publish the template (available for rendering).

        Transitions: DRAFT → PUBLISHED
        """
        if self._status != TemplateStatus.DRAFT:
            raise InvalidTemplateTransitionError(str(self._status), "published")
        self._status = TemplateStatus.PUBLISHED
        self._touch()
        self._record_event(
            TemplatePublished(
                occurred_at=_now(),
                template_id=str(self._id),
                version=str(self._version),
            )
        )

    def archive(self) -> None:
        """Archive the template.

        Transitions: PUBLISHED → ARCHIVED
        """
        if self._status != TemplateStatus.PUBLISHED:
            raise InvalidTemplateTransitionError(str(self._status), "archived")
        self._status = TemplateStatus.ARCHIVED
        self._touch()
        self._record_event(
            TemplateArchived(occurred_at=_now(), template_id=str(self._id))
        )

    # ─── Rendering ────────────────────────────────────────────────────────

    def render(self, context: RenderContext) -> RenderedPayload:
        """Render the template with the given context.

        Resolves all {{variable}} placeholders using the context.
        Only published templates can be rendered.
        """
        if not self.is_renderable:
            raise TemplateRenderError(
                str(self._id), "Template is not published"
            )

        # Validate required variables
        missing = []
        for var in self._variables:
            if var.required and not context.get(var.name) and not var.default_value:
                missing.append(var.name)
        if missing:
            raise TemplateRenderError(
                str(self._id),
                f"Missing required variables: {', '.join(missing)}",
            )

        # Resolve variables in body
        def _resolve(match: re.Match[str]) -> str:
            var_name = match.group(1)
            # Check context first, then defaults
            value = context.get(var_name)
            if value:
                return value
            for var in self._variables:
                if var.name == var_name and var.default_value:
                    return var.default_value
            return match.group(0)  # Leave unresolved

        rendered_content = _VAR_PATTERN.sub(_resolve, self._body)
        variables_used = {
            var.name: context.get(var.name, var.default_value)
            for var in self._variables
        }

        return RenderedPayload(
            content=rendered_content,
            template_id=str(self._id),
            variables_used=variables_used,
        )

    # ─── Modification ─────────────────────────────────────────────────────

    def tag(self, value: str) -> None:
        self._require_mutable()
        self._tags.add(value.strip().lower())
        self._touch()

    def untag(self, value: str) -> None:
        self._require_mutable()
        self._tags.discard(value.strip().lower())
        self._touch()

    # ─── Events ───────────────────────────────────────────────────────────

    def collect_events(self) -> list[PayloadEvent]:
        events = self._events.copy()
        self._events.clear()
        return events

    # ─── Private ──────────────────────────────────────────────────────────

    def _require_mutable(self) -> None:
        if self._status == TemplateStatus.ARCHIVED:
            raise TemplateArchivedError(str(self._id))

    def _touch(self) -> None:
        self._timestamps = self._timestamps.mark_updated()

    def _record_event(self, event: PayloadEvent) -> None:
        self._events.append(event)

    # ─── Equality ─────────────────────────────────────────────────────────

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, PayloadTemplate):
            return NotImplemented
        return self._id == other._id

    def __hash__(self) -> int:
        return hash(self._id)

    def __repr__(self) -> str:
        return (
            f"PayloadTemplate(id={self._id}, name={self._name!r}, "
            f"type={self._template_type}, status={self._status})"
        )
