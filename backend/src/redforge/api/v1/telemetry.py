"""Customer-owned telemetry ingestion and query API — M18.

Ingestion endpoints accept Suricata EVE JSON or Zeek JSON records for
sensors registered under the caller's organization. All ingestion is:
  - Authenticated (NETWORK_SECURITY_MANAGE for write paths)
  - Read-only queried by SECURITY_OPERATIONS_READ
  - Batch-size limited (max 1000 records per call)
  - Body-size limited (max 10 MB per request)
  - Deduplicated on source_event_id
  - Private-IP enrichment-blocked

organization_id is always derived from the caller's verified token —
never accepted from the client.
"""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator

from redforge.api.dependencies import _session_factory
from redforge.api.security import TenantContext, require_permission
from redforge.domain.identity.value_objects import Permission

router = APIRouter(prefix="/telemetry", tags=["telemetry"])

_MAX_BATCH = 1000
_MAX_LINE_LEN = 65_536


# ── Request / Response models ──────────────────────────────────────────────


class RegisterSensorRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    format: str = Field(..., description="suricata_eve or zeek_json")
    description: str = Field(default="", max_length=1000)
    token_ref: str | None = Field(
        default=None,
        max_length=200,
        description="Env-var or vault path for the ingestion token — never the raw token",
    )

    @field_validator("format")
    @classmethod
    def validate_format(cls, v: str) -> str:
        allowed = {"suricata_eve", "zeek_json"}
        if v not in allowed:
            raise ValueError(f"format must be one of {sorted(allowed)}")
        return v


class SensorResponse(BaseModel):
    id: str
    name: str
    format: str
    description: str
    enabled: bool
    created_at: str


class IngestRequest(BaseModel):
    sensor_id: str
    records: list[str] = Field(
        ...,
        max_length=_MAX_BATCH,
        description="Raw JSON-lines (one EVE/Zeek record per element)",
    )
    # For Zeek: optional log type hint (e.g. 'conn', 'notice') when the
    # log type isn't in each record's _path field.
    log_type_hint: str | None = Field(default=None)

    @field_validator("records")
    @classmethod
    def validate_record_lengths(cls, v: list[str]) -> list[str]:
        for rec in v:
            if len(rec) > _MAX_LINE_LEN:
                raise ValueError(f"record exceeds maximum line length ({_MAX_LINE_LEN} bytes)")
        return v


class IngestResponse(BaseModel):
    sensor_id: str
    total_submitted: int
    created: int
    duplicate: int
    parse_error: int
    ingest_error: int


class TelemetryEventResponse(BaseModel):
    id: str
    sensor_id: str
    sensor_name: str
    source_event_id: str
    format: str
    event_type: str
    event_ts: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str | None
    action: str | None
    severity: str | None
    signature: str | None
    signature_id: str | None
    bytes_in: int | None
    bytes_out: int | None
    packets_in: int | None
    packets_out: int | None
    enrichment_state: str
    ingested_at: str


class BandwidthSummaryResponse(BaseModel):
    period_hours: int
    total_bytes_in: int | None
    total_bytes_out: int | None
    total_packets_in: int | None
    total_packets_out: int | None
    flow_count: int
    top_talkers: list[dict[str, object]]
    top_destination_ports: list[dict[str, object]]
    has_real_data: bool


# ── Sensor management ─────────────────────────────────────────────────────


@router.get("/sensors", response_model=list[SensorResponse])
async def list_sensors(
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
) -> list[SensorResponse]:
    from redforge.application.telemetry.query_service import TelemetryQueryService

    async with _session_factory()() as session:
        svc = TelemetryQueryService(session)
        sensors = await svc.list_sensors(tenant.organization_id)
    return [SensorResponse(**asdict(s)) for s in sensors]


@router.post("/sensors", response_model=SensorResponse, status_code=status.HTTP_201_CREATED)
async def register_sensor(
    body: RegisterSensorRequest,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
) -> SensorResponse:
    from redforge.application.telemetry.query_service import TelemetryQueryService
    from redforge.application.telemetry.sensor_service import (
        SensorAlreadyExistsError,
        TelemetrySensorService,
        UnknownFormatError,
    )

    async with _session_factory()() as session:
        async with session.begin():
            svc = TelemetrySensorService(session)
            try:
                sensor_id = await svc.register_sensor(
                    organization_id=tenant.organization_id,
                    created_by=tenant.user_id,
                    name=body.name,
                    format=body.format,
                    description=body.description,
                    token_ref=body.token_ref,
                )
            except UnknownFormatError as e:
                raise HTTPException(status_code=422, detail=str(e)) from e
            except SensorAlreadyExistsError as e:
                raise HTTPException(status_code=409, detail=str(e)) from e

        query_svc = TelemetryQueryService(session)
        sensors = await query_svc.list_sensors(tenant.organization_id)
    sensor = next((s for s in sensors if s.id == sensor_id), None)
    if sensor is None:
        raise HTTPException(status_code=500, detail="sensor created but not retrievable")
    return SensorResponse(**asdict(sensor))


@router.delete("/sensors/{sensor_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_sensor(
    sensor_id: str,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
) -> None:
    from redforge.application.telemetry.sensor_service import TelemetrySensorService

    async with _session_factory()() as session, session.begin():
        svc = TelemetrySensorService(session)
        removed = await svc.remove_sensor(tenant.organization_id, sensor_id)
    if not removed:
        raise HTTPException(status_code=404, detail="sensor not found")


# ── Telemetry ingestion ────────────────────────────────────────────────────


@router.post("/ingest", response_model=IngestResponse)
async def ingest_events(
    body: IngestRequest,
    tenant: TenantContext = Depends(require_permission(Permission.NETWORK_SECURITY_MANAGE)),
) -> IngestResponse:
    """Ingest a batch of Suricata EVE JSON or Zeek JSON records.
    Records are parsed, normalized, and persisted idempotently.
    Malformed records are counted and skipped — they never crash the batch.
    Private IPs are never sent to external enrichment providers."""
    from redforge.application.telemetry.ingestion_service import TelemetryIngestionService
    from redforge.infrastructure.telemetry.parsers import suricata_eve, zeek_json

    if not body.records:
        return IngestResponse(
            sensor_id=body.sensor_id,
            total_submitted=0,
            created=0,
            duplicate=0,
            parse_error=0,
            ingest_error=0,
        )

    # Determine format from the sensor (verified against org at ingest time)
    async with _session_factory()() as session:
        from redforge.infrastructure.database.repositories.telemetry_repository import (
            SqlAlchemyTelemetrySensorRepository,
        )

        sensor_repo = SqlAlchemyTelemetrySensorRepository(session)
        sensor = await sensor_repo.get_by_id(tenant.organization_id, body.sensor_id)

    if sensor is None:
        raise HTTPException(status_code=404, detail="sensor not found")
    if not sensor.enabled:
        raise HTTPException(status_code=409, detail="sensor is disabled")

    fmt = sensor.format
    parse_error = 0
    parsed_events: list[suricata_eve.ParsedEvent | zeek_json.ParsedEvent] = []

    if fmt == "suricata_eve":
        evts, _skipped, errors = suricata_eve.parse_batch(list(body.records), _MAX_BATCH)
        parsed_events = list(evts)
        parse_error = errors
    elif fmt == "zeek_json":
        evts_z, _skipped, errors = zeek_json.parse_batch(
            list(body.records), log_type=body.log_type_hint, max_records=_MAX_BATCH
        )
        parsed_events = list(evts_z)
        parse_error = errors
    else:
        raise HTTPException(status_code=422, detail=f"unsupported format: {fmt}")

    if not parsed_events:
        return IngestResponse(
            sensor_id=body.sensor_id,
            total_submitted=len(body.records),
            created=0,
            duplicate=0,
            parse_error=parse_error,
            ingest_error=0,
        )

    async with _session_factory()() as session, session.begin():
        svc = TelemetryIngestionService(session)
        try:
            summary = await svc.ingest_batch(
                organization_id=tenant.organization_id,
                sensor_id=body.sensor_id,
                events=parsed_events,
            )
        except ValueError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e

    return IngestResponse(
        sensor_id=body.sensor_id,
        total_submitted=len(body.records),
        created=summary.created,
        duplicate=summary.duplicate,
        parse_error=parse_error,
        ingest_error=summary.error,
    )


# ── Query endpoints ────────────────────────────────────────────────────────


@router.get("/events", response_model=list[TelemetryEventResponse])
async def list_events(
    sensor_id: str | None = Query(default=None),
    event_type: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
) -> list[TelemetryEventResponse]:
    from redforge.application.telemetry.query_service import TelemetryQueryService

    async with _session_factory()() as session:
        svc = TelemetryQueryService(session)
        events = await svc.list_events(
            tenant.organization_id,
            sensor_id=sensor_id,
            event_type=event_type,
            limit=limit,
            offset=offset,
        )
    return [TelemetryEventResponse(**asdict(e)) for e in events]


@router.get("/bandwidth", response_model=BandwidthSummaryResponse)
async def get_bandwidth_summary(
    period_hours: int = Query(default=24, ge=1, le=168),
    tenant: TenantContext = Depends(require_permission(Permission.SECURITY_OPERATIONS_READ)),
) -> BandwidthSummaryResponse:
    """Network traffic / bandwidth summary from flow/netflow events that
    carry real byte and packet counts. Returns has_real_data=false when no
    traffic-metric events exist — never fabricates bandwidth numbers."""
    from redforge.application.telemetry.query_service import TelemetryQueryService

    async with _session_factory()() as session:
        svc = TelemetryQueryService(session)
        summary = await svc.get_bandwidth_summary(tenant.organization_id, period_hours)
    return BandwidthSummaryResponse(**asdict(summary))
