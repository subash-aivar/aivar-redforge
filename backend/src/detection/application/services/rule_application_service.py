"""Detection rule application service — Phase 1 use cases."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from detection.application._validation import (
    validate_limit,
    validate_offset,
    validate_str,
    validate_uuid,
)
from detection.application.dtos.rule_dtos import (
    DetectionRuleDTO,
    RulePageDTO,
    RuleTestSuiteResultDTO,
    ValidateRuleResultDTO,
)
from detection.application.exceptions import (
    ApplicationConflictError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from detection.domain.aggregates.detection_rule import DetectionRule
from detection.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    InvalidStateTransition,
    RulePromotionBlocked,
    TenantMismatch,
)
from detection.domain.value_objects.enums import (
    ConditionOperator,
    LogicConnector,
    RuleCategory,
    RuleConfidence,
    RuleLifecycleState,
    RuleLogicType,
    RuleSeverity,
)
from detection.domain.value_objects.identifiers import DetectionRuleId
from detection.domain.value_objects.keys import (
    AssetScopeFilter,
    AuthorRef,
    ExternalRuleRef,
    ReviewerRef,
    RuleKey,
    RuleSemVer,
    RuleTag,
    TelemetrySourceRef,
    ThrottlePolicy,
)
from detection.domain.value_objects.rule_logic import (
    NormalizedFieldRef,
    RuleCondition,
    RuleLogic,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from detection.application.commands.rule_commands import (
        AuthorDetectionRule,
        DemoteRule,
        PromoteRule,
        PublishRuleVersion,
        RunRuleTestSuite,
        UpdateRule,
        UpsertTestCase,
        ValidateRule,
    )
    from detection.application.ports.i_event_publisher import IEventPublisher
    from detection.application.ports.i_unit_of_work import IUnitOfWork
    from detection.application.queries.rule_queries import GetRule, ListRules

logger = logging.getLogger(__name__)


class RuleApplicationService:
    """Orchestrates DetectionRule mutations and reads with event publishing."""

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher

    async def _publish(self, aggregates: list[Any]) -> None:
        events: list[Any] = []
        for aggregate in aggregates:
            events.extend(aggregate.pop_events())
        try:
            await self._event_publisher.publish_batch(events)
        except Exception as exc:
            logger.warning("Event publication failed: %s", exc)

    def _map_invalid(self, exc: InvalidArgument) -> ApplicationValidationError:
        return ApplicationValidationError(exc.name, exc.message)

    def _parse_enum(self, enum_cls: type[Any], value: str, field: str) -> Any:
        try:
            return enum_cls(value)
        except ValueError as exc:
            raise ApplicationValidationError(field, f"invalid {field}: {value}") from exc

    def _parse_condition(self, raw: dict[str, Any]) -> RuleCondition:
        connector_raw = raw.get("connector")
        children_raw = raw.get("children") or []
        return RuleCondition(
            field=NormalizedFieldRef(str(raw["field"])),
            operator=ConditionOperator(str(raw["operator"])),
            value=raw.get("value"),
            connector=(
                LogicConnector(str(connector_raw)) if connector_raw is not None else None
            ),
            children=tuple(self._parse_condition(child) for child in children_raw),
        )

    def _parse_logic(self, raw: dict[str, Any]) -> RuleLogic:
        try:
            seq_seconds = raw.get("sequence_window_seconds")
            thresh_seconds = raw.get("threshold_window_seconds")
            refs_raw = raw.get("normalized_field_refs") or []
            corr_raw = raw.get("correlation_refs") or []
            return RuleLogic(
                logic_type=RuleLogicType(str(raw["logic_type"])),
                conditions=tuple(
                    self._parse_condition(item) for item in (raw.get("conditions") or [])
                ),
                sequence_window=(
                    timedelta(seconds=int(seq_seconds)) if seq_seconds is not None else None
                ),
                aggregation_field=raw.get("aggregation_field"),
                threshold_count=raw.get("threshold_count"),
                threshold_window=(
                    timedelta(seconds=int(thresh_seconds))
                    if thresh_seconds is not None
                    else None
                ),
                correlation_refs=tuple(RuleKey(str(ref)) for ref in corr_raw),
                normalized_field_refs=tuple(
                    NormalizedFieldRef(str(path)) for path in refs_raw
                ),
            )
        except (InvalidArgument, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, InvalidArgument):
                raise self._map_invalid(exc) from exc
            raise ApplicationValidationError("logic", str(exc)) from exc
    def _parse_telemetry(
        self, raw: list[dict[str, str | None]]
    ) -> list[TelemetrySourceRef]:
        refs: list[TelemetrySourceRef] = []
        for item in raw:
            try:
                refs.append(
                    TelemetrySourceRef(
                        source_id=str(item["source_id"]),
                        source_type=item.get("source_type"),
                    )
                )
            except (InvalidArgument, KeyError, TypeError) as exc:
                if isinstance(exc, InvalidArgument):
                    raise self._map_invalid(exc) from exc
                raise ApplicationValidationError(
                    "telemetry_sources", "each entry requires source_id"
                ) from exc
        return refs

    def _parse_asset_scope(
        self, raw: dict[str, list[str]] | None
    ) -> AssetScopeFilter | None:
        if raw is None:
            return None
        try:
            return AssetScopeFilter(
                asset_types=tuple(str(t) for t in (raw.get("asset_types") or ())),
                tags=tuple(str(t) for t in (raw.get("tags") or ())),
            )
        except InvalidArgument as exc:
            raise self._map_invalid(exc) from exc

    def _parse_throttle(self, raw: dict[str, int] | None) -> ThrottlePolicy | None:
        if raw is None:
            return None
        try:
            return ThrottlePolicy(
                window_seconds=int(raw["window_seconds"]),
                max_count=int(raw["max_count"]),
            )
        except (InvalidArgument, KeyError, TypeError, ValueError) as exc:
            if isinstance(exc, InvalidArgument):
                raise self._map_invalid(exc) from exc
            raise ApplicationValidationError(
                "throttle", "requires window_seconds and max_count"
            ) from exc

    def _parse_tags(self, raw: list[str]) -> list[RuleTag]:
        try:
            return [RuleTag(tag) for tag in raw]
        except InvalidArgument as exc:
            raise self._map_invalid(exc) from exc

    def _parse_external_refs(
        self, raw: list[dict[str, str]]
    ) -> list[ExternalRuleRef]:
        refs: list[ExternalRuleRef] = []
        for item in raw:
            try:
                refs.append(
                    ExternalRuleRef(
                        system=str(item["system"]),
                        external_id=str(item["external_id"]),
                    )
                )
            except (InvalidArgument, KeyError, TypeError) as exc:
                if isinstance(exc, InvalidArgument):
                    raise self._map_invalid(exc) from exc
                raise ApplicationValidationError(
                    "external_refs", "each entry requires system and external_id"
                ) from exc
        return refs

    async def author_detection_rule(self, cmd: AuthorDetectionRule) -> DetectionRuleDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_str(cmd.rule_key, "rule_key", 256)
        validate_str(cmd.title, "title", 512)
        validate_str(cmd.description, "description", 8192, allow_empty=True)
        validate_str(cmd.author_identity, "author_identity", 256)

        category = self._parse_enum(RuleCategory, cmd.category, "category")
        severity = self._parse_enum(RuleSeverity, cmd.severity, "severity")
        confidence = self._parse_enum(RuleConfidence, cmd.confidence, "confidence")
        logic = self._parse_logic(cmd.logic)
        tenant_id = cmd.tenant_id

        try:
            rule_key = RuleKey(cmd.rule_key)
            author = AuthorRef(cmd.author_identity)
        except InvalidArgument as exc:
            raise self._map_invalid(exc) from exc

        telemetry = self._parse_telemetry(cmd.telemetry_sources)
        asset_scope = self._parse_asset_scope(cmd.asset_scope)
        throttle = self._parse_throttle(cmd.throttle)
        tags = self._parse_tags(cmd.tags)
        external_refs = self._parse_external_refs(cmd.external_refs)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            existing = await uow.detection_rules.find_by_key(rule_key, tenant_id)
            if existing is not None:
                raise ApplicationConflictError(
                    f"DetectionRule already exists for key {rule_key.value}"
                )

            try:
                aggregate = DetectionRule.create(
                    tenant_id=tenant_id,
                    rule_key=rule_key,
                    title=cmd.title,
                    description=cmd.description,
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    author=author,
                    logic=logic,
                    now=now,
                    telemetry_sources=telemetry,
                    asset_scope=asset_scope,
                    throttle_policy=throttle,
                    tags=tags,
                    external_refs=external_refs,
                )
            except InvalidArgument as exc:
                raise self._map_invalid(exc) from exc

            for case in cmd.test_cases:
                name = str(case.get("name", ""))
                if not name:
                    raise ApplicationValidationError("test_cases", "each case requires name")
                try:
                    aggregate.upsert_test_case(
                        tenant_id=tenant_id,
                        name=name,
                        input_payload=dict(case.get("input_payload") or {}),
                        expected_match=bool(case.get("expected_match", True)),
                        actor=cmd.author_identity,
                        now=now,
                        description=case.get("description"),
                    )
                except InvalidArgument as exc:
                    raise self._map_invalid(exc) from exc

            await uow.detection_rules.save(aggregate)
            await uow.commit()
            await self._publish([aggregate])
            return DetectionRuleDTO.from_aggregate(aggregate)

    async def publish_rule_version(self, cmd: PublishRuleVersion) -> DetectionRuleDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.rule_id, "rule_id")
        validate_str(cmd.change_summary, "change_summary", 4096)
        validate_str(cmd.published_by, "published_by", 256)

        tenant_id = cmd.tenant_id
        rule_id = DetectionRuleId(cmd.rule_id)
        logic = self._parse_logic(cmd.logic) if cmd.logic is not None else None
        semver = None
        if cmd.semver is not None:
            try:
                semver = RuleSemVer.parse(cmd.semver)
            except InvalidArgument as exc:
                raise self._map_invalid(exc) from exc

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            aggregate = await uow.detection_rules.find_by_id(rule_id, tenant_id)
            if aggregate is None:
                raise ApplicationNotFoundError("DetectionRule", str(rule_id))
            try:
                aggregate.publish_version(
                    tenant_id=tenant_id,
                    semver=semver,
                    change_summary=cmd.change_summary,
                    published_by=cmd.published_by,
                    logic=logic,
                    now=now,
                )
            except (InvalidArgument, InvalidStateTransition, TenantMismatch) as exc:
                if isinstance(exc, InvalidArgument):
                    raise self._map_invalid(exc) from exc
                raise

            await uow.detection_rules.save(aggregate)
            await uow.commit()
            await self._publish([aggregate])
            return DetectionRuleDTO.from_aggregate(aggregate)

    async def promote_rule(self, cmd: PromoteRule) -> DetectionRuleDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.rule_id, "rule_id")
        validate_str(cmd.actor, "actor", 256)
        target = self._parse_enum(RuleLifecycleState, cmd.target_state, "target_state")
        reviewer = None
        if cmd.reviewer_identity is not None:
            validate_str(cmd.reviewer_identity, "reviewer_identity", 256)
            try:
                reviewer = ReviewerRef(cmd.reviewer_identity)
            except InvalidArgument as exc:
                raise self._map_invalid(exc) from exc

        tenant_id = cmd.tenant_id
        rule_id = DetectionRuleId(cmd.rule_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            aggregate = await uow.detection_rules.find_by_id(rule_id, tenant_id)
            if aggregate is None:
                raise ApplicationNotFoundError("DetectionRule", str(rule_id))
            try:
                aggregate.promote(
                    tenant_id=tenant_id,
                    target=target,
                    actor=cmd.actor,
                    now=now,
                    reviewer=reviewer,
                )
            except (
                InvalidArgument,
                InvalidStateTransition,
                RulePromotionBlocked,
                TenantMismatch,
            ) as exc:
                if isinstance(exc, InvalidArgument):
                    raise self._map_invalid(exc) from exc
                if isinstance(exc, RulePromotionBlocked):
                    raise ApplicationConflictError(str(exc)) from exc
                raise

            await uow.detection_rules.save(aggregate)
            await uow.commit()
            await self._publish([aggregate])
            return DetectionRuleDTO.from_aggregate(aggregate)

    async def demote_rule(self, cmd: DemoteRule) -> DetectionRuleDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.rule_id, "rule_id")
        validate_str(cmd.actor, "actor", 256)
        validate_str(cmd.reason, "reason", 4096)
        target = self._parse_enum(RuleLifecycleState, cmd.target_state, "target_state")

        tenant_id = cmd.tenant_id
        rule_id = DetectionRuleId(cmd.rule_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            aggregate = await uow.detection_rules.find_by_id(rule_id, tenant_id)
            if aggregate is None:
                raise ApplicationNotFoundError("DetectionRule", str(rule_id))
            try:
                aggregate.demote(
                    tenant_id=tenant_id,
                    target=target,
                    actor=cmd.actor,
                    reason=cmd.reason,
                    now=now,
                )
            except (InvalidArgument, InvalidStateTransition, TenantMismatch) as exc:
                if isinstance(exc, InvalidArgument):
                    raise self._map_invalid(exc) from exc
                raise

            await uow.detection_rules.save(aggregate)
            await uow.commit()
            await self._publish([aggregate])
            return DetectionRuleDTO.from_aggregate(aggregate)

    async def run_rule_test_suite(
        self, cmd: RunRuleTestSuite
    ) -> RuleTestSuiteResultDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.rule_id, "rule_id")

        tenant_id = cmd.tenant_id
        rule_id = DetectionRuleId(cmd.rule_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            aggregate = await uow.detection_rules.find_by_id(rule_id, tenant_id)
            if aggregate is None:
                raise ApplicationNotFoundError("DetectionRule", str(rule_id))
            try:
                results = aggregate.run_test_suite(tenant_id=tenant_id, now=now)
            except (InvalidArgument, TenantMismatch) as exc:
                if isinstance(exc, InvalidArgument):
                    raise self._map_invalid(exc) from exc
                raise

            await uow.detection_rules.save(aggregate)
            await uow.commit()
            await self._publish([aggregate])
            return RuleTestSuiteResultDTO.from_results(str(rule_id), results)

    async def validate_rule(self, cmd: ValidateRule) -> ValidateRuleResultDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.rule_id, "rule_id")

        tenant_id = cmd.tenant_id
        rule_id = DetectionRuleId(cmd.rule_id)

        async with self._uow_factory() as uow:
            aggregate = await uow.detection_rules.find_by_id(rule_id, tenant_id)
            if aggregate is None:
                raise ApplicationNotFoundError("DetectionRule", str(rule_id))
            try:
                aggregate.validate_logic()
            except InvalidArgument as exc:
                raise self._map_invalid(exc) from exc
            return ValidateRuleResultDTO(rule_id=str(rule_id), valid=True)

    async def update_rule(self, cmd: UpdateRule) -> DetectionRuleDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.rule_id, "rule_id")

        severity = (
            self._parse_enum(RuleSeverity, cmd.severity, "severity")
            if cmd.severity is not None
            else None
        )
        confidence = (
            self._parse_enum(RuleConfidence, cmd.confidence, "confidence")
            if cmd.confidence is not None
            else None
        )
        throttle = self._parse_throttle(cmd.throttle)
        tags = self._parse_tags(cmd.tags) if cmd.tags is not None else None

        tenant_id = cmd.tenant_id
        rule_id = DetectionRuleId(cmd.rule_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            aggregate = await uow.detection_rules.find_by_id(rule_id, tenant_id)
            if aggregate is None:
                raise ApplicationNotFoundError("DetectionRule", str(rule_id))
            try:
                aggregate.update_metadata(
                    tenant_id=tenant_id,
                    now=now,
                    title=cmd.title,
                    description=cmd.description,
                    severity=severity,
                    confidence=confidence,
                    throttle_policy=throttle,
                    tags=tags,
                )
                if cmd.test_cases is not None:
                    for case in cmd.test_cases:
                        name = str(case.get("name", ""))
                        if not name:
                            raise ApplicationValidationError(
                                "test_cases", "each case requires name"
                            )
                        aggregate.upsert_test_case(
                            tenant_id=tenant_id,
                            name=name,
                            input_payload=dict(case.get("input_payload") or {}),
                            expected_match=bool(case.get("expected_match", True)),
                            actor=cmd.actor,
                            now=now,
                            description=case.get("description"),
                        )
            except (InvalidArgument, InvalidStateTransition, TenantMismatch) as exc:
                if isinstance(exc, InvalidArgument):
                    raise self._map_invalid(exc) from exc
                raise

            await uow.detection_rules.save(aggregate)
            await uow.commit()
            await self._publish([aggregate])
            return DetectionRuleDTO.from_aggregate(aggregate)

    async def upsert_test_case(self, cmd: UpsertTestCase) -> DetectionRuleDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        validate_uuid(cmd.rule_id, "rule_id")
        validate_str(cmd.name, "name", 256)
        validate_str(cmd.actor, "actor", 256)

        tenant_id = cmd.tenant_id
        rule_id = DetectionRuleId(cmd.rule_id)
        now = datetime.now(UTC)

        async with self._uow_factory() as uow:
            aggregate = await uow.detection_rules.find_by_id(rule_id, tenant_id)
            if aggregate is None:
                raise ApplicationNotFoundError("DetectionRule", str(rule_id))
            try:
                aggregate.upsert_test_case(
                    tenant_id=tenant_id,
                    name=cmd.name,
                    input_payload=cmd.input_payload,
                    expected_match=cmd.expected_match,
                    actor=cmd.actor,
                    now=now,
                    description=cmd.description,
                )
            except (InvalidArgument, TenantMismatch) as exc:
                if isinstance(exc, InvalidArgument):
                    raise self._map_invalid(exc) from exc
                raise

            await uow.detection_rules.save(aggregate)
            await uow.commit()
            await self._publish([aggregate])
            return DetectionRuleDTO.from_aggregate(aggregate)

    async def get_rule(self, qry: GetRule) -> DetectionRuleDTO:
        validate_uuid(qry.tenant_id, "tenant_id")
        validate_uuid(qry.rule_id, "rule_id")

        tenant_id = qry.tenant_id
        rule_id = DetectionRuleId(qry.rule_id)

        async with self._uow_factory() as uow:
            aggregate = await uow.detection_rules.find_by_id(rule_id, tenant_id)
            if aggregate is None:
                raise ApplicationNotFoundError("DetectionRule", str(rule_id))
            return DetectionRuleDTO.from_aggregate(aggregate)

    async def list_rules(self, qry: ListRules) -> RulePageDTO:
        validate_uuid(qry.tenant_id, "tenant_id")
        limit = validate_limit(qry.limit)
        offset = validate_offset(qry.offset)
        tenant_id = qry.tenant_id

        async with self._uow_factory() as uow:
            if qry.lifecycle_state is not None:
                state = self._parse_enum(
                    RuleLifecycleState, qry.lifecycle_state, "lifecycle_state"
                )
                items = await uow.detection_rules.find_by_lifecycle_state(
                    tenant_id, state
                )
                # Apply pagination in-memory for filtered list
                page_items = items[offset : offset + limit]
                return RulePageDTO(
                    items=[DetectionRuleDTO.from_aggregate(r) for r in page_items],
                    total=len(items),
                    limit=limit,
                    offset=offset,
                )

            items = await uow.detection_rules.list_by_tenant(
                tenant_id, limit=limit, offset=offset
            )
            return RulePageDTO(
                items=[DetectionRuleDTO.from_aggregate(r) for r in items],
                total=len(items),
                limit=limit,
                offset=offset,
            )
