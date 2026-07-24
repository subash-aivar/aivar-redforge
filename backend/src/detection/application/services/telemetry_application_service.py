"""TelemetrySource + simulation application service — Phase 2 use cases."""

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
from detection.application.dtos.telemetry_dtos import (
    SchemaValidationResultDTO,
    SimulationResultDTO,
    TelemetrySourceDTO,
    TelemetrySourcePageDTO,
    ValidateSourceResultDTO,
)
from detection.application.exceptions import (
    ApplicationConflictError,
    ApplicationNotFoundError,
    ApplicationValidationError,
)
from detection.domain.aggregates.telemetry_source import TelemetrySource
from detection.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    InvalidStateTransition,
    ProviderNotRegistered,
    SchemaVersionMismatch,
    SimulationBlocked,
    TenantMismatch,
)
from detection.domain.providers.normalized_models import (
    NormalizedTelemetryEvent,
    NormalizedTelemetryResult,
)
from detection.domain.services.schema_validation import SchemaValidator
from detection.domain.services.simulation import RuleSimulationService
from detection.domain.value_objects.enums import (
    FieldDataType,
    SourceHealthStatus,
    SourceTrustLevel,
    SourceType,
)
from detection.domain.value_objects.identifiers import (
    DetectionRuleId,
    TelemetrySourceId,
)
from detection.domain.value_objects.rule_logic import NormalizedFieldRef
from detection.domain.value_objects.telemetry import (
    ConnectionConfig,
    DataLatencyProfile,
    FieldDefinition,
    RetentionWindow,
    SourceSchema,
    TimeWindow,
)
from detection.infrastructure.persistence.serialization import (
    connection_to_json,
    health_to_json,
    source_schema_to_json,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from detection.application.commands.telemetry_commands import (
        DeactivateTelemetrySource,
        RegisterTelemetrySource,
        SimulateRule,
        UpdateTelemetrySource,
        UpdateTelemetrySourceHealth,
        ValidateRuleAgainstSchema,
    )
    from detection.application.ports.i_event_publisher import IEventPublisher
    from detection.application.ports.i_telemetry_query_port import ITelemetryQueryPort
    from detection.application.ports.i_unit_of_work import IUnitOfWork
    from detection.application.queries.telemetry_queries import (
        GetTelemetrySource,
        ListTelemetrySources,
    )
    from detection.domain.providers.registry import TelemetryProviderRegistry

logger = logging.getLogger(__name__)


class TelemetryApplicationService:
    """Orchestrates TelemetrySource, schema validation, and isolated simulation."""

    def __init__(
        self,
        uow_factory: Callable[[], IUnitOfWork],
        event_publisher: IEventPublisher,
        provider_registry: TelemetryProviderRegistry,
        query_port: ITelemetryQueryPort,
    ) -> None:
        self._uow_factory = uow_factory
        self._event_publisher = event_publisher
        self._registry = provider_registry
        self._query_port = query_port
        self._schema_validator = SchemaValidator()
        self._simulation = RuleSimulationService()

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

    def _to_dto(self, source: TelemetrySource) -> TelemetrySourceDTO:
        return TelemetrySourceDTO(
            id=str(source.source_id),
            tenant_id=str(source.tenant_id),
            name=source.name,
            source_type=source.source_type.value,
            trust_level=source.trust_level.value,
            lifecycle_state=source.lifecycle_state.value,
            description=source.description,
            schema_version=source.schema.schema_version,
            schema=source_schema_to_json(source.schema),
            connection=connection_to_json(source.connection),
            health_status=source.health.status.value,
            health=health_to_json(source.health),
            latency_expected_seconds=source.latency_profile.expected_latency.total_seconds(),
            latency_max_seconds=(
                source.latency_profile.max_acceptable_latency.total_seconds()
                if source.latency_profile.max_acceptable_latency is not None
                else None
            ),
            retention_seconds=source.retention.retention.total_seconds(),
            created_at=source.created_at.isoformat(),
            updated_at=source.updated_at.isoformat(),
            version=source.version,
        )

    def _parse_fields(self, fields: list[dict[str, Any]]) -> tuple[FieldDefinition, ...]:
        if not fields:
            raise ApplicationValidationError("fields", "schema fields required")
        parsed: list[FieldDefinition] = []
        for item in fields:
            path = str(item.get("path") or "")
            validate_str(path, "path", max_len=256)
            dtype = str(item.get("data_type") or FieldDataType.STRING.value)
            try:
                field_type = FieldDataType(dtype)
            except ValueError as exc:
                raise ApplicationValidationError("data_type", f"invalid: {dtype}") from exc
            parsed.append(
                FieldDefinition(
                    field_ref=NormalizedFieldRef(path),
                    data_type=field_type,
                    required=bool(item.get("required", False)),
                    description=str(item.get("description") or ""),
                )
            )
        return tuple(parsed)

    async def register_telemetry_source(
        self, cmd: RegisterTelemetrySource
    ) -> TelemetrySourceDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        tenant_id = cmd.tenant_id
        validate_str(cmd.name, "name", max_len=256)
        name = cmd.name.strip()
        try:
            source_type = SourceType(cmd.source_type)
            trust_level = SourceTrustLevel(cmd.trust_level)
        except ValueError as exc:
            raise ApplicationValidationError("validation", str(exc)) from exc

        validate_str(cmd.schema_version, "schema_version", max_len=64)
        schema_version = cmd.schema_version.strip()
        validate_str(cmd.adapter_key, "adapter_key", max_len=128)
        adapter_key = cmd.adapter_key.strip()
        validate_str(
            cmd.tenant_scope_assertion, "tenant_scope_assertion", max_len=512
        )
        tenant_scope = cmd.tenant_scope_assertion.strip()
        if cmd.latency_expected_seconds < 0:
            raise ApplicationValidationError("latency_expected_seconds", "must be >= 0")
        if cmd.retention_seconds <= 0:
            raise ApplicationValidationError("retention_seconds", "must be > 0")

        try:
            schema = SourceSchema(
                schema_version=schema_version,
                fields=self._parse_fields(cmd.fields),
            )
            connection = ConnectionConfig(
                adapter_key=adapter_key,
                tenant_scope_assertion=tenant_scope,
                credential_vault_ref=cmd.credential_vault_ref,
                endpoint_url=cmd.endpoint_url,
                options=dict(cmd.options or {}),
            )
            latency = DataLatencyProfile(
                expected_latency=timedelta(seconds=cmd.latency_expected_seconds),
                max_acceptable_latency=(
                    timedelta(seconds=cmd.latency_max_seconds)
                    if cmd.latency_max_seconds is not None
                    else None
                ),
            )
            retention = RetentionWindow(retention=timedelta(seconds=cmd.retention_seconds))
        except InvalidArgument as exc:
            raise self._map_invalid(exc) from exc

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            existing = await uow.telemetry_sources.find_by_name(name, tenant_id)
            if existing is not None:
                raise ApplicationConflictError(f"TelemetrySource already exists: {name}")
            try:
                source = TelemetrySource.register(
                    tenant_id=tenant_id,
                    name=name,
                    source_type=source_type,
                    trust_level=trust_level,
                    schema=schema,
                    connection=connection,
                    latency_profile=latency,
                    retention=retention,
                    description=cmd.description,
                    now=now,
                )
            except InvalidArgument as exc:
                raise self._map_invalid(exc) from exc
            await uow.telemetry_sources.save(source)
            await uow.commit()
            await self._publish([source])
            return self._to_dto(source)

    async def deactivate_telemetry_source(
        self, cmd: DeactivateTelemetrySource
    ) -> TelemetrySourceDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        tenant_id = cmd.tenant_id
        validate_uuid(cmd.source_id, "source_id")
        source_id = TelemetrySourceId(cmd.source_id)
        validate_str(cmd.reason, "reason", max_len=1024)
        reason = cmd.reason.strip()
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            source = await uow.telemetry_sources.find_by_id(source_id, tenant_id)
            if source is None:
                raise ApplicationNotFoundError("TelemetrySource", str(source_id))
            try:
                source.deactivate(tenant_id=tenant_id, reason=reason, now=now)
            except (InvalidArgument, InvalidStateTransition, TenantMismatch) as exc:
                if isinstance(exc, InvalidArgument):
                    raise self._map_invalid(exc) from exc
                raise ApplicationValidationError("validation", str(exc)) from exc
            await uow.telemetry_sources.save(source)
            await uow.commit()
            await self._publish([source])
            return self._to_dto(source)

    async def update_telemetry_source_health(
        self, cmd: UpdateTelemetrySourceHealth
    ) -> TelemetrySourceDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        tenant_id = cmd.tenant_id
        validate_uuid(cmd.source_id, "source_id")
        source_id = TelemetrySourceId(cmd.source_id)
        try:
            status = SourceHealthStatus(cmd.status)
        except ValueError as exc:
            raise ApplicationValidationError("status", f"invalid: {cmd.status}") from exc
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            source = await uow.telemetry_sources.find_by_id(source_id, tenant_id)
            if source is None:
                raise ApplicationNotFoundError("TelemetrySource", str(source_id))
            try:
                source.update_health(
                    tenant_id=tenant_id,
                    status=status,
                    now=now,
                    detail=cmd.detail,
                    success=cmd.success,
                )
            except (InvalidArgument, TenantMismatch) as exc:
                raise ApplicationValidationError("validation", str(exc)) from exc
            await uow.telemetry_sources.save(source)
            await uow.commit()
            await self._publish([source])
            return self._to_dto(source)

    async def update_telemetry_source(
        self, cmd: UpdateTelemetrySource
    ) -> TelemetrySourceDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        tenant_id = cmd.tenant_id
        validate_uuid(cmd.source_id, "source_id")
        source_id = TelemetrySourceId(cmd.source_id)
        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            source = await uow.telemetry_sources.find_by_id(source_id, tenant_id)
            if source is None:
                raise ApplicationNotFoundError("TelemetrySource", str(source_id))
            try:
                if cmd.fields is not None or cmd.schema_version is not None:
                    version = cmd.schema_version or source.schema.schema_version
                    fields = (
                        self._parse_fields(cmd.fields)
                        if cmd.fields is not None
                        else source.schema.fields
                    )
                    source.update_schema(
                        tenant_id=tenant_id,
                        schema=SourceSchema(schema_version=version, fields=fields),
                        now=now,
                    )
                if any(
                    x is not None
                    for x in (
                        cmd.adapter_key,
                        cmd.tenant_scope_assertion,
                        cmd.endpoint_url,
                        cmd.options,
                    )
                ):
                    source.update_connection(
                        tenant_id=tenant_id,
                        connection=ConnectionConfig(
                            adapter_key=cmd.adapter_key or source.connection.adapter_key,
                            tenant_scope_assertion=(
                                cmd.tenant_scope_assertion
                                or source.connection.tenant_scope_assertion
                            ),
                            credential_vault_ref=source.connection.credential_vault_ref,
                            endpoint_url=(
                                cmd.endpoint_url
                                if cmd.endpoint_url is not None
                                else source.connection.endpoint_url
                            ),
                            options=(
                                dict(cmd.options)
                                if cmd.options is not None
                                else dict(source.connection.options)
                            ),
                        ),
                        now=now,
                    )
                trust = (
                    SourceTrustLevel(cmd.trust_level)
                    if cmd.trust_level is not None
                    else None
                )
                latency = None
                if cmd.latency_expected_seconds is not None:
                    latency = DataLatencyProfile(
                        expected_latency=timedelta(seconds=cmd.latency_expected_seconds),
                        max_acceptable_latency=(
                            timedelta(seconds=cmd.latency_max_seconds)
                            if cmd.latency_max_seconds is not None
                            else source.latency_profile.max_acceptable_latency
                        ),
                    )
                retention = (
                    RetentionWindow(retention=timedelta(seconds=cmd.retention_seconds))
                    if cmd.retention_seconds is not None
                    else None
                )
                source.update_metadata(
                    tenant_id=tenant_id,
                    now=now,
                    description=cmd.description,
                    trust_level=trust,
                    latency_profile=latency,
                    retention=retention,
                )
            except (InvalidArgument, TenantMismatch, ValueError) as exc:
                raise ApplicationValidationError("validation", str(exc)) from exc
            await uow.telemetry_sources.save(source)
            await uow.commit()
            await self._publish([source])
            return self._to_dto(source)

    async def get_telemetry_source(
        self, query: GetTelemetrySource
    ) -> TelemetrySourceDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        tenant_id = query.tenant_id
        validate_uuid(query.source_id, "source_id")
        source_id = TelemetrySourceId(query.source_id)
        async with self._uow_factory() as uow:
            source = await uow.telemetry_sources.find_by_id(source_id, tenant_id)
            if source is None:
                raise ApplicationNotFoundError("TelemetrySource", str(source_id))
            return self._to_dto(source)

    async def list_telemetry_sources(
        self, query: ListTelemetrySources
    ) -> TelemetrySourcePageDTO:
        validate_uuid(query.tenant_id, "tenant_id")
        tenant_id = query.tenant_id
        limit = validate_limit(query.limit)
        offset = validate_offset(query.offset)
        async with self._uow_factory() as uow:
            if query.source_type:
                try:
                    st = SourceType(query.source_type)
                except ValueError as exc:
                    raise ApplicationValidationError("validation", str(exc)) from exc
                items = await uow.telemetry_sources.find_by_type(st, tenant_id)
            elif query.active_only:
                items = await uow.telemetry_sources.find_active_by_tenant(tenant_id)
            else:
                items = await uow.telemetry_sources.list_by_tenant(
                    tenant_id, limit=limit, offset=offset
                )
            needs_slice = bool(query.source_type) or query.active_only
            page = items[offset : offset + limit] if needs_slice else items
            return TelemetrySourcePageDTO(
                items=[self._to_dto(s) for s in page],
                limit=limit,
                offset=offset,
            )

    async def validate_telemetry_source(
        self,
        *,
        tenant_id: Any,
        source_id: Any,
    ) -> ValidateSourceResultDTO:
        validate_uuid(tenant_id, "tenant_id")
        tid = tenant_id
        validate_uuid(source_id, "source_id")
        sid = TelemetrySourceId(source_id)
        async with self._uow_factory() as uow:
            source = await uow.telemetry_sources.find_by_id(sid, tid)
            if source is None:
                raise ApplicationNotFoundError("TelemetrySource", str(sid))

        registered = self._registry.has_provider(
            source.source_type, source.schema.schema_version
        )
        schema_ok = False
        health: str | None = None
        caps: list[str] = []
        detail: str | None = None
        if registered:
            try:
                self._registry.validate_schema_version(
                    source.source_type, source.schema.schema_version
                )
                schema_ok = True
                health = self._registry.validate_health(
                    source.source_type, source.schema.schema_version
                ).value
                adapter = self._registry.lookup(
                    source.source_type, source.schema.schema_version
                )
                caps = sorted(adapter.capabilities)
            except (ProviderNotRegistered, SchemaVersionMismatch) as exc:
                detail = str(exc)
        else:
            detail = "no provider registered for source type/schema version"
        return ValidateSourceResultDTO(
            source_id=str(sid),
            provider_registered=registered,
            schema_version_valid=schema_ok,
            health_status=health,
            capabilities=caps,
            detail=detail,
        )

    async def validate_rule_against_schema(
        self, cmd: ValidateRuleAgainstSchema
    ) -> SchemaValidationResultDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        tenant_id = cmd.tenant_id
        validate_uuid(cmd.rule_id, "rule_id")
        rule_id = DetectionRuleId(cmd.rule_id)
        validate_uuid(cmd.source_id, "source_id")
        source_id = TelemetrySourceId(cmd.source_id)
        async with self._uow_factory() as uow:
            rule = await uow.detection_rules.find_by_id(rule_id, tenant_id)
            if rule is None:
                raise ApplicationNotFoundError("DetectionRule", str(rule_id))
            source = await uow.telemetry_sources.find_by_id(source_id, tenant_id)
            if source is None:
                raise ApplicationNotFoundError("TelemetrySource", str(source_id))

            logic = rule.current_logic
            if cmd.version:
                version_entity = next(
                    (v for v in rule.versions if str(v.semver) == cmd.version),
                    None,
                )
                if version_entity is None:
                    raise ApplicationNotFoundError("RuleVersion", str(cmd.version))
                logic = version_entity.logic

            result = self._schema_validator.validate_against_source(logic, source)
            return SchemaValidationResultDTO(
                is_valid=result.is_valid,
                missing_fields=list(result.missing_fields),
                unsupported_fields=list(result.unsupported_fields),
                issues=[
                    {
                        "field_path": i.field_path,
                        "issue_type": i.issue_type,
                        "message": i.message,
                    }
                    for i in result.issues
                ],
                schema_version=result.schema_version,
                compatible=result.compatible,
            )

    async def simulate_rule(self, cmd: SimulateRule) -> SimulationResultDTO:
        validate_uuid(cmd.tenant_id, "tenant_id")
        tenant_id = cmd.tenant_id
        validate_uuid(cmd.rule_id, "rule_id")
        rule_id = DetectionRuleId(cmd.rule_id)
        validate_uuid(cmd.source_id, "source_id")
        source_id = TelemetrySourceId(cmd.source_id)
        try:
            start = datetime.fromisoformat(cmd.window_start)
            end = datetime.fromisoformat(cmd.window_end)
            if start.tzinfo is None:
                start = start.replace(tzinfo=UTC)
            if end.tzinfo is None:
                end = end.replace(tzinfo=UTC)
            window = TimeWindow(start=start, end=end)
        except (ValueError, InvalidArgument) as exc:
            raise ApplicationValidationError("window", str(exc)) from exc

        now = datetime.now(UTC)
        async with self._uow_factory() as uow:
            rule = await uow.detection_rules.find_by_id(rule_id, tenant_id)
            if rule is None:
                raise ApplicationNotFoundError("DetectionRule", str(rule_id))
            source = await uow.telemetry_sources.find_by_id(source_id, tenant_id)
            if source is None:
                raise ApplicationNotFoundError("TelemetrySource", str(source_id))

            logic = rule.current_logic
            if cmd.version:
                version_entity = next(
                    (v for v in rule.versions if str(v.semver) == cmd.version),
                    None,
                )
                if version_entity is None:
                    raise ApplicationNotFoundError("RuleVersion", str(cmd.version))
                logic = version_entity.logic

            # Schema gate before simulation
            schema_result = self._schema_validator.validate_against_source(logic, source)
            if not schema_result.is_valid:
                raise ApplicationValidationError(
                    "schema",
                    f"validation failed: missing={list(schema_result.missing_fields)}",
                )

            query = self._simulation.build_query(logic, window, limit=cmd.limit)

            if cmd.synthetic_events is not None:
                events = tuple(
                    NormalizedTelemetryEvent(
                        fields={str(k): v for k, v in item.items()},
                        event_time=str(item.get("event.event_time"))
                        if item.get("event.event_time")
                        else None,
                    )
                    for item in cmd.synthetic_events
                )
                telemetry = NormalizedTelemetryResult(events=events)
            else:
                telemetry = await self._query_port.execute_query(
                    source_id=source_id,
                    tenant_id=tenant_id,
                    query=query,
                    window=window,
                )

            try:
                result = self._simulation.simulate(
                    rule=rule,
                    source=source,
                    window=window,
                    telemetry=telemetry,
                    now=now,
                    rule_version=cmd.version,
                )
            except SimulationBlocked as exc:
                raise ApplicationValidationError("validation", str(exc)) from exc

        # Isolation invariant: never create findings
        assert result.creates_findings is False
        return SimulationResultDTO(
            simulation_id=str(result.simulation_id),
            rule_id=str(result.rule_id),
            rule_version=result.rule_version,
            source_id=result.source_id,
            match_count=result.statistics.match_count,
            events_evaluated=result.statistics.events_evaluated,
            duration_ms=result.statistics.duration_ms,
            truncated=result.statistics.truncated,
            source_unavailable=result.statistics.source_unavailable,
            sample_matches=[dict(s.fields) for s in result.sample_matches],
            evidence={
                "evidence_type": result.evidence.evidence_type,
                "rule_id": result.evidence.rule_id,
                "rule_version": result.evidence.rule_version,
                "source_id": result.evidence.source_id,
                "window_start": result.evidence.window_start,
                "window_end": result.evidence.window_end,
                "match_count": result.evidence.match_count,
                "simulated_at": result.evidence.simulated_at,
                "payload_summary": dict(result.evidence.payload_summary),
            },
            simulated_at=result.simulated_at.isoformat(),
            creates_findings=False,
            findings_created=0,
        )
