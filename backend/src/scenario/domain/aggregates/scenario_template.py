"""ScenarioTemplate aggregate root — reusable parameterized attack scenario blueprint."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from scenario.domain.events.scenario_events import (
    ScenarioInstantiated,
    ScenarioTemplateCreated,
    ScenarioTemplateDeprecated,
    ScenarioTemplatePublished,
)
from scenario.domain.exceptions.domain_exceptions import (
    CannotPublishWithoutParameterDefaults,
    CannotPublishWithoutTechniques,
    InvalidTemplateState,
    TemplateImmutableWhenPublished,
    TenantMismatch,
)
from scenario.domain.value_objects.enums import ScenarioTemplateState

if TYPE_CHECKING:
    from datetime import datetime

    from scenario.domain.entities.scenario_entities import ScenarioParameter, ScenarioPhase
    from scenario.domain.events.base import BaseDomainEvent
    from scenario.domain.value_objects.identifiers import ScenarioTemplateId, TenantId
    from scenario.domain.value_objects.scenario_vos import (
        CoveredAttackTechniques,
        DefaultSafetyPolicy,
        ScenarioKey,
        ScenarioObjectiveBlueprint,
        ScenarioTemplateVersion,
        TaskGraphTopologyBlueprint,
        ThreatActorRef,
    )


class ScenarioTemplate:
    """Parameterized attack scenario blueprint with ATT&CK coverage targets.

    Published versions are immutable. Instantiation produces draft specs only —
    it does not auto-approve campaigns (ADR-M30-006).
    """

    __slots__ = (
        "_pending_events",
        "_version",
        "covered_techniques",
        "created_at",
        "default_safety_policy",
        "description",
        "name",
        "objective_blueprints",
        "parameters",
        "phases",
        "scenario_key",
        "state",
        "suggested_approval_fast_path",
        "task_graph_topology",
        "template_id",
        "tenant_id",
        "threat_actor_ref",
        "updated_at",
        "version_label",
    )

    def __init__(
        self,
        template_id: ScenarioTemplateId,
        tenant_id: TenantId,
        scenario_key: ScenarioKey,
        version_label: ScenarioTemplateVersion,
        name: str,
        description: str,
        state: ScenarioTemplateState,
        threat_actor_ref: ThreatActorRef | None,
        covered_techniques: CoveredAttackTechniques,
        objective_blueprints: list[ScenarioObjectiveBlueprint],
        default_safety_policy: DefaultSafetyPolicy,
        task_graph_topology: TaskGraphTopologyBlueprint,
        parameters: list[ScenarioParameter],
        phases: list[ScenarioPhase],
        suggested_approval_fast_path: str | None,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.template_id = template_id
        self.tenant_id = tenant_id
        self.scenario_key = scenario_key
        self.version_label = version_label
        self.name = name
        self.description = description
        self.state = state
        self.threat_actor_ref = threat_actor_ref
        self.covered_techniques = covered_techniques
        self.objective_blueprints = list(objective_blueprints)
        self.default_safety_policy = default_safety_policy
        self.task_graph_topology = task_graph_topology
        self.parameters = list(parameters)
        self.phases = list(phases)
        self.suggested_approval_fast_path = suggested_approval_fast_path
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _mutate(self, now: datetime) -> None:
        self._version += 1
        self.updated_at = now

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _assert_mutable(self) -> None:
        if self.state != ScenarioTemplateState.DRAFT:
            raise TemplateImmutableWhenPublished(str(self.template_id), self.state.value)

    @classmethod
    def create(
        cls,
        template_id: ScenarioTemplateId,
        tenant_id: TenantId,
        scenario_key: ScenarioKey,
        version_label: ScenarioTemplateVersion,
        name: str,
        description: str,
        threat_actor_ref: ThreatActorRef | None,
        covered_techniques: CoveredAttackTechniques,
        objective_blueprints: list[ScenarioObjectiveBlueprint],
        default_safety_policy: DefaultSafetyPolicy,
        task_graph_topology: TaskGraphTopologyBlueprint,
        parameters: list[ScenarioParameter],
        phases: list[ScenarioPhase],
        suggested_approval_fast_path: str | None,
        now: datetime,
    ) -> ScenarioTemplate:
        if not name.strip():
            raise ValueError("ScenarioTemplate name is required")

        template = cls(
            template_id=template_id,
            tenant_id=tenant_id,
            scenario_key=scenario_key,
            version_label=version_label,
            name=name.strip(),
            description=description,
            state=ScenarioTemplateState.DRAFT,
            threat_actor_ref=threat_actor_ref,
            covered_techniques=covered_techniques,
            objective_blueprints=objective_blueprints,
            default_safety_policy=default_safety_policy,
            task_graph_topology=task_graph_topology,
            parameters=parameters,
            phases=phases,
            suggested_approval_fast_path=suggested_approval_fast_path,
            created_at=now,
            updated_at=now,
            version=1,
        )
        template._emit(
            ScenarioTemplateCreated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(template_id),
                aggregate_type="ScenarioTemplate",
                scenario_key=scenario_key.value,
                version=version_label.value,
                name=template.name,
            )
        )
        return template

    def publish(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.state != ScenarioTemplateState.DRAFT:
            raise InvalidTemplateState(self.state.value, "publish")

        if not self.covered_techniques.techniques:
            raise CannotPublishWithoutTechniques(str(self.template_id))

        missing_defaults = tuple(
            p.name
            for p in self.parameters
            if p.required and p.default_value is None
        )
        if missing_defaults:
            raise CannotPublishWithoutParameterDefaults(
                str(self.template_id), missing_defaults
            )

        self.state = ScenarioTemplateState.PUBLISHED
        self._mutate(now)
        self._emit(
            ScenarioTemplatePublished(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.template_id),
                aggregate_type="ScenarioTemplate",
                scenario_key=self.scenario_key.value,
                version=self.version_label.value,
                technique_count=len(self.covered_techniques.techniques),
                threat_actor_id=(
                    self.threat_actor_ref.threat_actor_id
                    if self.threat_actor_ref
                    else None
                ),
            )
        )

    def deprecate(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.state != ScenarioTemplateState.PUBLISHED:
            raise InvalidTemplateState(self.state.value, "deprecate")

        self.state = ScenarioTemplateState.DEPRECATED
        self._mutate(now)
        self._emit(
            ScenarioTemplateDeprecated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.template_id),
                aggregate_type="ScenarioTemplate",
                scenario_key=self.scenario_key.value,
                version=self.version_label.value,
            )
        )

    def archive(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.state not in {
            ScenarioTemplateState.PUBLISHED,
            ScenarioTemplateState.DEPRECATED,
        }:
            raise InvalidTemplateState(self.state.value, "archive")

        self.state = ScenarioTemplateState.ARCHIVED
        self._mutate(now)

    def instantiate_recorded(
        self,
        tenant_id: TenantId,
        now: datetime,
    ) -> None:
        """Record that a campaign draft was produced from this template."""
        self._assert_tenant(tenant_id)
        if self.state != ScenarioTemplateState.PUBLISHED:
            raise InvalidTemplateState(self.state.value, "instantiate_recorded")

        self._emit(
            ScenarioInstantiated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.template_id),
                aggregate_type="ScenarioTemplate",
                scenario_key=self.scenario_key.value,
                version=self.version_label.value,
                instantiated_by_tenant_id=str(tenant_id),
            )
        )
