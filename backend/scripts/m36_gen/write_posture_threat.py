"""Generate posture_forecasting and threat_hunt bounded contexts."""

from __future__ import annotations

from .common import SRC, TESTS, empty_inits, w


def write() -> None:
    _posture()
    _threat()


def _posture() -> None:
    base = SRC / "posture_forecasting"
    empty_inits(
        base,
        base / "domain",
        base / "domain" / "aggregates",
        base / "domain" / "events",
        base / "domain" / "exceptions",
        base / "domain" / "repositories",
        base / "domain" / "services",
        base / "domain" / "value_objects",
        base / "application",
        base / "application" / "commands",
        base / "application" / "dtos",
        base / "application" / "services",
        base / "infrastructure",
        base / "infrastructure" / "persistence",
        base / "infrastructure" / "workers",
        base / "infrastructure" / "acl",
        base / "api",
        base / "api" / "v1",
    )
    w(base / "__init__.py", '"""M36 posture_forecasting bounded context."""\n')
    w(base / "py.typed", "")
    w(
        base / "domain" / "value_objects" / "identifiers.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class ForecastId:
    value: UUID

    @classmethod
    def generate(cls) -> ForecastId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
''',
    )
    w(
        base / "domain" / "value_objects" / "snapshots.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from posture_forecasting.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True, kw_only=True)
class ForecastInputSnapshot:
    baseline_exposure_score: float
    remediation_velocity_per_day: float
    open_critical_count: int
    open_high_count: int
    snapshot_at: datetime
    tenant_id: TenantId


@dataclass
class ForecastAccuracyRecord:
    horizon_days: int
    actual_score: float
    predicted_score: float
    absolute_error: float
    recorded_at: datetime
''',
    )
    w(
        base / "domain" / "exceptions" / "domain_exceptions.py",
        '''from __future__ import annotations


class PostureForecastingDomainError(Exception):
    pass


class DomainInvariantViolation(PostureForecastingDomainError):
    pass


class TenantMismatch(PostureForecastingDomainError):
    pass
''',
    )
    w(
        base / "domain" / "events" / "forecast_events.py",
        '''from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class BaseForecastEvent:
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str = ""
    aggregate_id: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class PostureForecastGenerated(BaseForecastEvent):
    forecast_id: str
    predicted_30d: float
    predicted_60d: float
    predicted_90d: float


@dataclass(frozen=True, slots=True, kw_only=True)
class ForecastAccuracyRecorded(BaseForecastEvent):
    forecast_id: str
    horizon_days: int
    absolute_error: float
''',
    )
    w(
        base / "domain" / "aggregates" / "posture_forecast.py",
        '''from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from posture_forecasting.domain.events.forecast_events import (
    ForecastAccuracyRecorded,
    PostureForecastGenerated,
)
from posture_forecasting.domain.exceptions.domain_exceptions import DomainInvariantViolation
from posture_forecasting.domain.value_objects.identifiers import ForecastId, TenantId
from posture_forecasting.domain.value_objects.snapshots import (
    ForecastAccuracyRecord,
    ForecastInputSnapshot,
)


class PostureForecast:
    __slots__ = (
        "_pending_events",
        "accuracy_records",
        "forecast_id",
        "generated_at",
        "input_snapshot",
        "model_id",
        "model_version",
        "predicted_30d",
        "predicted_60d",
        "predicted_90d",
        "tenant_id",
    )

    def __init__(
        self,
        forecast_id: ForecastId,
        tenant_id: TenantId,
        input_snapshot: ForecastInputSnapshot,
        predicted_30d: float,
        predicted_60d: float,
        predicted_90d: float,
        model_id: str,
        model_version: int,
        generated_at: datetime,
        *,
        accuracy_records: list[ForecastAccuracyRecord] | None = None,
    ) -> None:
        if input_snapshot is None:
            raise DomainInvariantViolation("input_snapshot required")
        if input_snapshot.tenant_id.value != tenant_id.value:
            raise DomainInvariantViolation("snapshot tenant mismatch")
        self.forecast_id = forecast_id
        self.tenant_id = tenant_id
        self.input_snapshot = input_snapshot
        self.predicted_30d = predicted_30d
        self.predicted_60d = predicted_60d
        self.predicted_90d = predicted_90d
        self.model_id = model_id
        self.model_version = model_version
        self.generated_at = generated_at
        self.accuracy_records = list(accuracy_records or [])
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        input_snapshot: ForecastInputSnapshot,
        predicted_30d: float,
        predicted_60d: float,
        predicted_90d: float,
        model_id: str,
        model_version: int,
    ) -> PostureForecast:
        now = datetime.now(UTC)
        forecast = cls(
            ForecastId.generate(),
            tenant_id,
            input_snapshot,
            predicted_30d,
            predicted_60d,
            predicted_90d,
            model_id,
            model_version,
            now,
        )
        forecast._pending_events.append(
            PostureForecastGenerated(
                tenant_id=str(tenant_id),
                aggregate_id=str(forecast.forecast_id),
                forecast_id=str(forecast.forecast_id),
                predicted_30d=predicted_30d,
                predicted_60d=predicted_60d,
                predicted_90d=predicted_90d,
            )
        )
        return forecast

    def record_accuracy(
        self, horizon_days: int, actual_score: float, predicted_score: float
    ) -> None:
        now = datetime.now(UTC)
        err = abs(actual_score - predicted_score)
        self.accuracy_records.append(
            ForecastAccuracyRecord(horizon_days, actual_score, predicted_score, err, now)
        )
        self._pending_events.append(
            ForecastAccuracyRecorded(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.forecast_id),
                forecast_id=str(self.forecast_id),
                horizon_days=horizon_days,
                absolute_error=err,
            )
        )
''',
    )
    w(
        base / "domain" / "aggregates" / "forecast_configuration.py",
        '''from __future__ import annotations

from dataclasses import dataclass, field

from posture_forecasting.domain.value_objects.identifiers import TenantId


@dataclass
class ForecastConfiguration:
    tenant_id: TenantId
    forecast_frequency_hours: int = 24
    signal_weights: dict[str, float] = field(
        default_factory=lambda: {"exposure": 0.6, "remediation_velocity": 0.4}
    )

    @classmethod
    def default(cls, tenant_id: TenantId) -> ForecastConfiguration:
        return cls(tenant_id)
''',
    )
    w(
        base / "domain" / "services" / "forecast_generation_service.py",
        '''from __future__ import annotations

from posture_forecasting.domain.aggregates.posture_forecast import PostureForecast
from posture_forecasting.domain.value_objects.identifiers import TenantId
from posture_forecasting.domain.value_objects.snapshots import ForecastInputSnapshot


class ForecastGenerationService:
    def generate(
        self, tenant_id: TenantId, snapshot: ForecastInputSnapshot
    ) -> PostureForecast:
        # simple linear trajectory using remediation velocity
        decay = max(0.0, snapshot.remediation_velocity_per_day * 0.01)
        p30 = max(0.0, snapshot.baseline_exposure_score - decay * 30)
        p60 = max(0.0, snapshot.baseline_exposure_score - decay * 60)
        p90 = max(0.0, snapshot.baseline_exposure_score - decay * 90)
        return PostureForecast.create(
            tenant_id, snapshot, p30, p60, p90, "forecast-v1", 1
        )
''',
    )
    w(
        base / "domain" / "services" / "forecast_accuracy_service.py",
        '''from __future__ import annotations

from posture_forecasting.domain.aggregates.posture_forecast import PostureForecast


class ForecastAccuracyService:
    def record(
        self, forecast: PostureForecast, horizon_days: int, actual_score: float
    ) -> None:
        predicted = {
            30: forecast.predicted_30d,
            60: forecast.predicted_60d,
            90: forecast.predicted_90d,
        }[horizon_days]
        forecast.record_accuracy(horizon_days, actual_score, predicted)
''',
    )
    w(
        base / "domain" / "repositories" / "i_repositories.py",
        '''from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from posture_forecasting.domain.aggregates.forecast_configuration import ForecastConfiguration
from posture_forecasting.domain.aggregates.posture_forecast import PostureForecast
from posture_forecasting.domain.value_objects.identifiers import TenantId


class IPostureForecastRepository(ABC):
    @abstractmethod
    async def save(self, forecast: PostureForecast, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def find_latest(self, tenant_id: TenantId) -> PostureForecast | None: ...

    @abstractmethod
    async def find_pending_accuracy_check(
        self, horizon_days: int, cutoff: datetime
    ) -> list[PostureForecast]: ...


class IForecastConfigurationRepository(ABC):
    @abstractmethod
    async def get_or_create_default(self, tenant_id: TenantId) -> ForecastConfiguration: ...
''',
    )
    w(
        base / "application" / "exceptions.py",
        '''from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationNotFoundError(ApplicationError):
    pass


class ApplicationForbiddenError(ApplicationError):
    pass
''',
    )
    w(
        base / "application" / "_auth.py",
        '''from __future__ import annotations

from posture_forecasting.application.exceptions import ApplicationForbiddenError


def require_any(roles: tuple[str, ...], *allowed: str) -> None:
    if not any(r in roles for r in allowed):
        raise ApplicationForbiddenError(",".join(allowed))
''',
    )
    w(
        base / "application" / "commands" / "forecast_commands.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True, slots=True)
class GeneratePostureForecast:
    tenant_id: UUID
    baseline_exposure_score: float
    remediation_velocity_per_day: float
    open_critical_count: int
    open_high_count: int
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RecordForecastAccuracy:
    tenant_id: UUID
    forecast_id: UUID
    horizon_days: int
    actual_score: float
    roles: tuple[str, ...]
''',
    )
    w(
        base / "application" / "dtos" / "forecast_dtos.py",
        '''from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PostureForecastDTO:
    forecast_id: str
    tenant_id: str
    predicted_30d: float
    predicted_60d: float
    predicted_90d: float
    baseline_exposure_score: float
    generated_at: str
''',
    )
    w(
        base / "application" / "services" / "forecast_application_service.py",
        '''from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from posture_forecasting.application._auth import require_any
from posture_forecasting.application.commands.forecast_commands import (
    GeneratePostureForecast,
    RecordForecastAccuracy,
)
from posture_forecasting.application.dtos.forecast_dtos import PostureForecastDTO
from posture_forecasting.application.exceptions import ApplicationNotFoundError
from posture_forecasting.domain.services.forecast_accuracy_service import ForecastAccuracyService
from posture_forecasting.domain.services.forecast_generation_service import ForecastGenerationService
from posture_forecasting.domain.value_objects.identifiers import ForecastId, TenantId
from posture_forecasting.domain.value_objects.snapshots import ForecastInputSnapshot


class ForecastApplicationService:
    def __init__(self, forecasts: Any, configs: Any, event_sink: list[Any] | None = None) -> None:
        self._forecasts = forecasts
        self._configs = configs
        self._events: list[Any] = event_sink if event_sink is not None else []
        self._gen = ForecastGenerationService()
        self._acc = ForecastAccuracyService()

    def _tenant(self, value: UUID) -> TenantId:
        return TenantId(value)

    async def generate(self, cmd: GeneratePostureForecast) -> PostureForecastDTO:
        require_any(cmd.roles, "ai:operator", "system", "vuln:manager")
        tenant = self._tenant(cmd.tenant_id)
        await self._configs.get_or_create_default(tenant)
        snapshot = ForecastInputSnapshot(
            baseline_exposure_score=cmd.baseline_exposure_score,
            remediation_velocity_per_day=cmd.remediation_velocity_per_day,
            open_critical_count=cmd.open_critical_count,
            open_high_count=cmd.open_high_count,
            snapshot_at=datetime.now(UTC),
            tenant_id=tenant,
        )
        forecast = self._gen.generate(tenant, snapshot)
        await self._forecasts.save(forecast, tenant)
        self._events.extend(forecast.pop_events())
        return PostureForecastDTO(
            str(forecast.forecast_id),
            str(tenant),
            forecast.predicted_30d,
            forecast.predicted_60d,
            forecast.predicted_90d,
            snapshot.baseline_exposure_score,
            forecast.generated_at.isoformat(),
        )

    async def record_accuracy(self, cmd: RecordForecastAccuracy) -> PostureForecastDTO:
        require_any(cmd.roles, "ai:operator", "system")
        tenant = self._tenant(cmd.tenant_id)
        forecast = await self._forecasts.find_latest(tenant)
        if forecast is None or forecast.forecast_id.value != cmd.forecast_id:
            # allow lookup by scanning — latest only for simplicity
            raise ApplicationNotFoundError("forecast not found")
        self._acc.record(forecast, cmd.horizon_days, cmd.actual_score)
        await self._forecasts.save(forecast, tenant)
        self._events.extend(forecast.pop_events())
        return PostureForecastDTO(
            str(forecast.forecast_id),
            str(tenant),
            forecast.predicted_30d,
            forecast.predicted_60d,
            forecast.predicted_90d,
            forecast.input_snapshot.baseline_exposure_score,
            forecast.generated_at.isoformat(),
        )

    async def get_latest(self, tenant_id: UUID, roles: tuple[str, ...]) -> PostureForecastDTO:
        require_any(roles, "ai:operator", "vuln:manager", "playbook:analyst")
        forecast = await self._forecasts.find_latest(self._tenant(tenant_id))
        if forecast is None:
            raise ApplicationNotFoundError("forecast not found")
        return PostureForecastDTO(
            str(forecast.forecast_id),
            str(tenant_id),
            forecast.predicted_30d,
            forecast.predicted_60d,
            forecast.predicted_90d,
            forecast.input_snapshot.baseline_exposure_score,
            forecast.generated_at.isoformat(),
        )
''',
    )
    w(
        base / "infrastructure" / "persistence" / "in_memory_repositories.py",
        '''from __future__ import annotations

from datetime import datetime, timedelta

from posture_forecasting.domain.aggregates.forecast_configuration import ForecastConfiguration
from posture_forecasting.domain.aggregates.posture_forecast import PostureForecast
from posture_forecasting.domain.repositories.i_repositories import (
    IForecastConfigurationRepository,
    IPostureForecastRepository,
)
from posture_forecasting.domain.value_objects.identifiers import TenantId


class InMemoryPostureForecastRepository(IPostureForecastRepository):
    def __init__(self) -> None:
        self._items: dict[str, list[PostureForecast]] = {}

    async def save(self, forecast: PostureForecast, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), []).append(forecast)

    async def find_latest(self, tenant_id: TenantId) -> PostureForecast | None:
        rows = self._items.get(str(tenant_id), [])
        if not rows:
            return None
        return max(rows, key=lambda f: f.generated_at)

    async def find_pending_accuracy_check(
        self, horizon_days: int, cutoff: datetime
    ) -> list[PostureForecast]:
        out: list[PostureForecast] = []
        for rows in self._items.values():
            for f in rows:
                if f.generated_at <= cutoff - timedelta(days=horizon_days):
                    if not any(r.horizon_days == horizon_days for r in f.accuracy_records):
                        out.append(f)
        return out


class InMemoryForecastConfigurationRepository(IForecastConfigurationRepository):
    def __init__(self) -> None:
        self._items: dict[str, ForecastConfiguration] = {}

    async def get_or_create_default(self, tenant_id: TenantId) -> ForecastConfiguration:
        key = str(tenant_id)
        if key not in self._items:
            self._items[key] = ForecastConfiguration.default(tenant_id)
        return self._items[key]
''',
    )
    w(
        base / "infrastructure" / "acl" / "m32_exposure_translator.py",
        '''from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ExposureScoreUpdatedPayload:
    tenant_id: str
    exposure_score: float
    open_critical_count: int
    open_high_count: int
    remediation_velocity_per_day: float


@dataclass(frozen=True, slots=True)
class ForecastInputSignal:
    tenant_id: str
    exposure_score: float
    open_critical_count: int
    open_high_count: int
    remediation_velocity_per_day: float


class M32ExposureTranslator:
    def translate(self, payload: ExposureScoreUpdatedPayload) -> ForecastInputSignal | None:
        try:
            return ForecastInputSignal(
                payload.tenant_id,
                payload.exposure_score,
                payload.open_critical_count,
                payload.open_high_count,
                payload.remediation_velocity_per_day,
            )
        except Exception:  # noqa: BLE001
            return None
''',
    )
    w(
        base / "infrastructure" / "workers" / "forecast_workers.py",
        '''from __future__ import annotations

from typing import Any
from uuid import UUID

from posture_forecasting.application.commands.forecast_commands import GeneratePostureForecast


class PostureForecastWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.runs = 0

    async def tick(
        self,
        tenant_id: UUID,
        baseline: float = 50.0,
        velocity: float = 1.0,
        critical: int = 2,
        high: int = 5,
    ) -> Any:
        self.runs += 1
        return await self._app.generate(
            GeneratePostureForecast(
                tenant_id, baseline, velocity, critical, high, ("system",)
            )
        )


class ForecastAccuracyWorker:
    def __init__(self, forecasts: Any, accuracy_service: Any) -> None:
        self._forecasts = forecasts
        self._accuracy = accuracy_service
        self.runs = 0

    async def tick(self, tenant_id: UUID, actual_score: float = 40.0) -> int:
        from datetime import UTC, datetime

        from posture_forecasting.domain.value_objects.identifiers import TenantId

        self.runs += 1
        count = 0
        for horizon in (30, 60, 90):
            pending = await self._forecasts.find_pending_accuracy_check(
                horizon, datetime.now(UTC)
            )
            for forecast in pending:
                if str(forecast.tenant_id) != str(tenant_id):
                    continue
                self._accuracy.record(forecast, horizon, actual_score)
                await self._forecasts.save(forecast, TenantId(tenant_id))
                count += 1
        return count


class ForecastScheduler:
    def __init__(self, forecast_worker: PostureForecastWorker, accuracy_worker: ForecastAccuracyWorker) -> None:
        self.forecast_worker = forecast_worker
        self.accuracy_worker = accuracy_worker

    async def tick_all(self, tenant_id: UUID) -> dict[str, int]:
        await self.forecast_worker.tick(tenant_id)
        measured = await self.accuracy_worker.tick(tenant_id)
        return {"forecast_runs": self.forecast_worker.runs, "accuracy_updates": measured}
''',
    )
    w(
        base / "infrastructure" / "container.py",
        '''from __future__ import annotations

from posture_forecasting.application.services.forecast_application_service import (
    ForecastApplicationService,
)
from posture_forecasting.domain.services.forecast_accuracy_service import ForecastAccuracyService
from posture_forecasting.infrastructure.persistence.in_memory_repositories import (
    InMemoryForecastConfigurationRepository,
    InMemoryPostureForecastRepository,
)
from posture_forecasting.infrastructure.workers.forecast_workers import (
    ForecastAccuracyWorker,
    ForecastScheduler,
    PostureForecastWorker,
)


class PostureForecastingContainer:
    def __init__(self) -> None:
        self.forecasts = InMemoryPostureForecastRepository()
        self.configs = InMemoryForecastConfigurationRepository()
        self.event_sink: list[object] = []
        self.app = ForecastApplicationService(self.forecasts, self.configs, self.event_sink)
        self.forecast_worker = PostureForecastWorker(self.app)
        self.accuracy_worker = ForecastAccuracyWorker(
            self.forecasts, ForecastAccuracyService()
        )
        self.scheduler = ForecastScheduler(self.forecast_worker, self.accuracy_worker)
''',
    )
    w(
        base / "api" / "dependencies.py",
        '''from __future__ import annotations

from uuid import UUID

from fastapi import Header, Request

from posture_forecasting.infrastructure.container import PostureForecastingContainer


def get_container(request: Request) -> PostureForecastingContainer:
    c = getattr(request.app.state, "posture_forecasting_container", None)
    if c is None:
        c = PostureForecastingContainer()
        request.app.state.posture_forecasting_container = c
    return c


def tenant_id_header(x_tenant_id: UUID = Header(..., alias="X-Tenant-Id")) -> UUID:
    return x_tenant_id


def roles_header(x_roles: str = Header("", alias="X-Roles")) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_roles.split(",") if r.strip())
''',
    )
    w(
        base / "api" / "v1" / "__init__.py",
        "from posture_forecasting.api.v1.routes import router\n\n__all__ = ['router']\n",
    )
    w(
        base / "api" / "v1" / "routes.py",
        '''from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from posture_forecasting.api.dependencies import get_container, roles_header, tenant_id_header
from posture_forecasting.application.commands.forecast_commands import GeneratePostureForecast
from posture_forecasting.application.exceptions import (
    ApplicationForbiddenError,
    ApplicationNotFoundError,
)
from posture_forecasting.domain.exceptions.domain_exceptions import PostureForecastingDomainError
from posture_forecasting.infrastructure.container import PostureForecastingContainer

router = APIRouter(prefix="/posture-forecasting", tags=["posture-forecasting"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, PostureForecastingDomainError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


class GenerateBody(BaseModel):
    baseline_exposure_score: float
    remediation_velocity_per_day: float = 1.0
    open_critical_count: int = 0
    open_high_count: int = 0


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "context": "posture_forecasting"}


@router.post("/forecasts", status_code=201)
async def generate(
    body: GenerateBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PostureForecastingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.generate(
            GeneratePostureForecast(
                tenant_id,
                body.baseline_exposure_score,
                body.remediation_velocity_per_day,
                body.open_critical_count,
                body.open_high_count,
                roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.get("/forecasts/latest")
async def latest(
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: PostureForecastingContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        return asdict(await container.app.get_latest(tenant_id, roles))
    except Exception as exc:
        raise _map(exc) from exc
''',
    )
    # posture tests
    tbase = TESTS / "posture_forecasting"
    w(tbase / "__init__.py", "")
    w(
        tbase / "test_architecture.py",
        '''from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "posture_forecasting"


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "py.typed").is_file()


def test_no_upstream_domain_imports() -> None:
    bad = re.compile(r"from (detection|campaign|playbook|autonomous_intelligence|threat_hunt)\\.")
    for p in ROOT.rglob("*.py"):
        if "infrastructure/acl" in str(p):
            continue
        if bad.search(p.read_text()):
            raise AssertionError(p)
''',
    )
    w(
        tbase / "test_lifecycle.py",
        '''from __future__ import annotations

from uuid import uuid4

import pytest

from posture_forecasting.application.commands.forecast_commands import GeneratePostureForecast
from posture_forecasting.infrastructure.container import PostureForecastingContainer


@pytest.mark.asyncio
async def test_generate_forecast() -> None:
    c = PostureForecastingContainer()
    tenant = uuid4()
    dto = await c.app.generate(
        GeneratePostureForecast(tenant, 80.0, 2.0, 3, 10, ("ai:operator",))
    )
    assert dto.predicted_90d <= dto.predicted_30d
    latest = await c.app.get_latest(tenant, ("ai:operator",))
    assert latest.forecast_id == dto.forecast_id


@pytest.mark.asyncio
async def test_worker_tick() -> None:
    c = PostureForecastingContainer()
    await c.scheduler.tick_all(uuid4())
    assert c.forecast_worker.runs == 1
''',
    )
    w(
        tbase / "test_api.py",
        '''from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from posture_forecasting.api.v1.routes import router
from posture_forecasting.infrastructure.container import PostureForecastingContainer


@pytest.mark.asyncio
async def test_forecast_api() -> None:
    app = FastAPI()
    app.include_router(router)
    app.state.posture_forecasting_container = PostureForecastingContainer()
    headers = {"X-Tenant-Id": str(uuid4()), "X-Roles": "ai:operator"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/posture-forecasting/forecasts",
            json={"baseline_exposure_score": 70.0},
            headers=headers,
        )
        assert r.status_code == 201
''',
    )
    w(
        tbase / "test_bulk.py",
        '''from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from posture_forecasting.domain.aggregates.posture_forecast import PostureForecast
from posture_forecasting.domain.services.forecast_generation_service import ForecastGenerationService
from posture_forecasting.domain.value_objects.identifiers import TenantId
from posture_forecasting.domain.value_objects.snapshots import ForecastInputSnapshot
from posture_forecasting.infrastructure.acl.m32_exposure_translator import (
    ExposureScoreUpdatedPayload,
    M32ExposureTranslator,
)


@pytest.mark.parametrize("velocity", [0.0, 0.5, 1.0, 2.0, 5.0])
def test_forecast_decreases_with_velocity(velocity: float) -> None:
    tenant = TenantId(uuid4())
    snap = ForecastInputSnapshot(
        baseline_exposure_score=100.0,
        remediation_velocity_per_day=velocity,
        open_critical_count=1,
        open_high_count=2,
        snapshot_at=datetime.now(UTC),
        tenant_id=tenant,
    )
    f = ForecastGenerationService().generate(tenant, snap)
    assert f.predicted_30d >= f.predicted_90d


@pytest.mark.parametrize("horizon", [30, 60, 90])
def test_accuracy_record(horizon: int) -> None:
    tenant = TenantId(uuid4())
    snap = ForecastInputSnapshot(
        baseline_exposure_score=50.0,
        remediation_velocity_per_day=1.0,
        open_critical_count=0,
        open_high_count=0,
        snapshot_at=datetime.now(UTC),
        tenant_id=tenant,
    )
    f = PostureForecast.create(tenant, snap, 40, 30, 20, "m", 1)
    f.record_accuracy(horizon, 35.0, {30: 40, 60: 30, 90: 20}[horizon])
    assert f.accuracy_records[-1].horizon_days == horizon


def test_acl_translator() -> None:
    sig = M32ExposureTranslator().translate(
        ExposureScoreUpdatedPayload("t", 55.0, 1, 2, 1.5)
    )
    assert sig is not None
    assert sig.exposure_score == 55.0
''',
    )

    # Continue with threat_hunt in same function via _threat
    # (defined below)


def _threat() -> None:
    base = SRC / "threat_hunt"
    empty_inits(
        base,
        base / "domain",
        base / "domain" / "aggregates",
        base / "domain" / "events",
        base / "domain" / "exceptions",
        base / "domain" / "repositories",
        base / "domain" / "services",
        base / "domain" / "value_objects",
        base / "application",
        base / "application" / "commands",
        base / "application" / "dtos",
        base / "application" / "services",
        base / "application" / "ports",
        base / "infrastructure",
        base / "infrastructure" / "persistence",
        base / "infrastructure" / "workers",
        base / "infrastructure" / "acl",
        base / "infrastructure" / "llm",
        base / "api",
        base / "api" / "v1",
    )
    w(base / "__init__.py", '"""M36 threat_hunt bounded context."""\n')
    w(base / "py.typed", "")
    w(
        base / "domain" / "value_objects" / "enums.py",
        '''from __future__ import annotations

from enum import StrEnum


class ThreatHuntCandidateStatus(StrEnum):
    CANDIDATE = "candidate"
    UNDER_REVIEW = "under_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    PROMOTED = "promoted"


class DetectionRuleFormat(StrEnum):
    SIGMA = "sigma"
    KQL = "kql"
    SPL = "spl"
''',
    )
    w(
        base / "domain" / "value_objects" / "identifiers.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class CandidateId:
    value: UUID

    @classmethod
    def generate(cls) -> CandidateId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class AnomalySignalRef:
    signal_id: str
    source: str


@dataclass(frozen=True, slots=True)
class AttckTechniqueRef:
    technique_id: str
    name: str
''',
    )
    w(
        base / "domain" / "exceptions" / "domain_exceptions.py",
        '''from __future__ import annotations


class ThreatHuntDomainError(Exception):
    pass


class DomainInvariantViolation(ThreatHuntDomainError):
    pass


class TenantMismatch(ThreatHuntDomainError):
    pass


class AuthorizationDenied(ThreatHuntDomainError):
    pass


class InvalidCandidateTransition(ThreatHuntDomainError):
    pass


class TenantIsolationViolation(ThreatHuntDomainError):
    pass
''',
    )
    w(
        base / "domain" / "events" / "hunt_events.py",
        '''from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class BaseHuntEvent:
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str = ""
    aggregate_id: str = ""


@dataclass(frozen=True, slots=True, kw_only=True)
class ThreatHuntCandidateGenerated(BaseHuntEvent):
    candidate_id: str
    technique_coverage: tuple[str, ...]
    confidence_score: float


@dataclass(frozen=True, slots=True, kw_only=True)
class ThreatHuntCandidatePromoted(BaseHuntEvent):
    candidate_id: str
    promoted_rule_version_id: str
    promoted_by: str


@dataclass(frozen=True, slots=True, kw_only=True)
class ThreatHuntCandidateRejected(BaseHuntEvent):
    candidate_id: str
    rejected_by: str
    rejection_reason: str
''',
    )
    w(
        base / "domain" / "aggregates" / "threat_hunt_candidate.py",
        '''from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from threat_hunt.domain.events.hunt_events import (
    ThreatHuntCandidateGenerated,
    ThreatHuntCandidatePromoted,
    ThreatHuntCandidateRejected,
)
from threat_hunt.domain.exceptions.domain_exceptions import (
    AuthorizationDenied,
    DomainInvariantViolation,
    InvalidCandidateTransition,
    TenantMismatch,
)
from threat_hunt.domain.value_objects.enums import DetectionRuleFormat, ThreatHuntCandidateStatus
from threat_hunt.domain.value_objects.identifiers import (
    AnomalySignalRef,
    AttckTechniqueRef,
    CandidateId,
    TenantId,
)


class ThreatHuntCandidate:
    __slots__ = (
        "_pending_events",
        "anomaly_signal_refs",
        "candidate_id",
        "candidate_status",
        "confidence_score",
        "detection_logic_draft",
        "detection_rule_format",
        "generated_at",
        "promoted_rule_version_id",
        "review_notes",
        "reviewed_at",
        "reviewed_by",
        "technique_coverage",
        "tenant_id",
    )

    def __init__(
        self,
        candidate_id: CandidateId,
        tenant_id: TenantId,
        anomaly_signal_refs: tuple[AnomalySignalRef, ...],
        technique_coverage: tuple[AttckTechniqueRef, ...],
        detection_logic_draft: str,
        detection_rule_format: DetectionRuleFormat,
        confidence_score: float,
        candidate_status: ThreatHuntCandidateStatus,
        generated_at: datetime,
        *,
        promoted_rule_version_id: UUID | None = None,
        review_notes: str | None = None,
        reviewed_at: datetime | None = None,
        reviewed_by: str | None = None,
    ) -> None:
        self.candidate_id = candidate_id
        self.tenant_id = tenant_id
        self.anomaly_signal_refs = anomaly_signal_refs
        self.technique_coverage = technique_coverage
        self.detection_logic_draft = detection_logic_draft
        self.detection_rule_format = detection_rule_format
        self.confidence_score = confidence_score
        self.candidate_status = candidate_status
        self.generated_at = generated_at
        self.promoted_rule_version_id = promoted_rule_version_id
        self.review_notes = review_notes
        self.reviewed_at = reviewed_at
        self.reviewed_by = reviewed_by
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        anomaly_signal_refs: tuple[AnomalySignalRef, ...],
        technique_coverage: tuple[AttckTechniqueRef, ...],
        detection_logic_draft: str,
        detection_rule_format: DetectionRuleFormat,
        confidence_score: float,
    ) -> ThreatHuntCandidate:
        if not anomaly_signal_refs:
            raise DomainInvariantViolation("anomaly_signal_refs required")
        now = datetime.now(UTC)
        candidate = cls(
            CandidateId.generate(),
            tenant_id,
            anomaly_signal_refs,
            technique_coverage,
            detection_logic_draft,
            detection_rule_format,
            confidence_score,
            ThreatHuntCandidateStatus.CANDIDATE,
            now,
        )
        candidate._pending_events.append(
            ThreatHuntCandidateGenerated(
                tenant_id=str(tenant_id),
                aggregate_id=str(candidate.candidate_id),
                candidate_id=str(candidate.candidate_id),
                technique_coverage=tuple(t.technique_id for t in technique_coverage),
                confidence_score=confidence_score,
            )
        )
        return candidate

    def promote(
        self,
        tenant_id: TenantId,
        promoted_by: str,
        roles: tuple[str, ...],
        promoted_rule_version_id: UUID,
    ) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")
        if "soc:detection_engineer" not in roles:
            raise AuthorizationDenied("requires soc:detection_engineer")
        if self.candidate_status not in {
            ThreatHuntCandidateStatus.CANDIDATE,
            ThreatHuntCandidateStatus.UNDER_REVIEW,
            ThreatHuntCandidateStatus.ACCEPTED,
        }:
            raise InvalidCandidateTransition(self.candidate_status.value)
        now = datetime.now(UTC)
        self.candidate_status = ThreatHuntCandidateStatus.PROMOTED
        self.promoted_rule_version_id = promoted_rule_version_id
        self.reviewed_by = promoted_by
        self.reviewed_at = now
        self._pending_events.append(
            ThreatHuntCandidatePromoted(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.candidate_id),
                candidate_id=str(self.candidate_id),
                promoted_rule_version_id=str(promoted_rule_version_id),
                promoted_by=promoted_by,
            )
        )

    def reject(self, tenant_id: TenantId, rejected_by: str, reason: str, roles: tuple[str, ...]) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")
        if "soc:detection_engineer" not in roles:
            raise AuthorizationDenied("requires soc:detection_engineer")
        self.candidate_status = ThreatHuntCandidateStatus.REJECTED
        self.reviewed_by = rejected_by
        self.reviewed_at = datetime.now(UTC)
        self.review_notes = reason
        self._pending_events.append(
            ThreatHuntCandidateRejected(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.candidate_id),
                candidate_id=str(self.candidate_id),
                rejected_by=rejected_by,
                rejection_reason=reason,
            )
        )
''',
    )
    w(
        base / "domain" / "aggregates" / "threat_hunt_configuration.py",
        '''from __future__ import annotations

from dataclasses import dataclass, field

from threat_hunt.domain.value_objects.identifiers import TenantId


@dataclass
class ThreatHuntConfiguration:
    tenant_id: TenantId
    min_signal_strength: float = 0.5
    enabled_signal_types: list[str] = field(default_factory=lambda: ["anomaly", "beaconing"])

    @classmethod
    def default(cls, tenant_id: TenantId) -> ThreatHuntConfiguration:
        return cls(tenant_id)
''',
    )
    w(
        base / "domain" / "services" / "candidate_generation_service.py",
        '''from __future__ import annotations

from threat_hunt.domain.aggregates.threat_hunt_candidate import ThreatHuntCandidate
from threat_hunt.domain.value_objects.enums import DetectionRuleFormat
from threat_hunt.domain.value_objects.identifiers import (
    AnomalySignalRef,
    AttckTechniqueRef,
    TenantId,
)


class CandidateGenerationService:
    def create(
        self,
        tenant_id: TenantId,
        signals: tuple[AnomalySignalRef, ...],
        techniques: tuple[AttckTechniqueRef, ...],
        logic_draft: str,
        confidence: float,
        fmt: DetectionRuleFormat = DetectionRuleFormat.SIGMA,
    ) -> ThreatHuntCandidate:
        return ThreatHuntCandidate.create(
            tenant_id, signals, techniques, logic_draft, fmt, confidence
        )
''',
    )
    w(
        base / "domain" / "services" / "candidate_review_service.py",
        '''from __future__ import annotations

from uuid import UUID

from threat_hunt.domain.aggregates.threat_hunt_candidate import ThreatHuntCandidate
from threat_hunt.domain.value_objects.identifiers import TenantId


class CandidateReviewService:
    def promote(
        self,
        candidate: ThreatHuntCandidate,
        tenant_id: TenantId,
        promoted_by: str,
        roles: tuple[str, ...],
        rule_version_id: UUID,
    ) -> None:
        candidate.promote(tenant_id, promoted_by, roles, rule_version_id)

    def reject(
        self,
        candidate: ThreatHuntCandidate,
        tenant_id: TenantId,
        rejected_by: str,
        reason: str,
        roles: tuple[str, ...],
    ) -> None:
        candidate.reject(tenant_id, rejected_by, reason, roles)
''',
    )
    w(
        base / "domain" / "repositories" / "i_repositories.py",
        '''from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID

from threat_hunt.domain.aggregates.threat_hunt_candidate import ThreatHuntCandidate
from threat_hunt.domain.aggregates.threat_hunt_configuration import ThreatHuntConfiguration
from threat_hunt.domain.value_objects.identifiers import TenantId


class IThreatHuntCandidateRepository(ABC):
    @abstractmethod
    async def save(self, candidate: ThreatHuntCandidate, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def find_pending_review(
        self, tenant_id: TenantId, limit: int
    ) -> list[ThreatHuntCandidate]: ...

    @abstractmethod
    async def find_by_id(
        self, candidate_id: UUID, tenant_id: TenantId
    ) -> ThreatHuntCandidate | None: ...


class IThreatHuntConfigurationRepository(ABC):
    @abstractmethod
    async def get_or_create_default(self, tenant_id: TenantId) -> ThreatHuntConfiguration: ...
''',
    )
    w(
        base / "application" / "ports" / "i_llm_inference_port.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True, slots=True)
class HuntLLMPrompt:
    tenant_id: UUID
    task: str
    context: str


@dataclass(frozen=True, slots=True)
class HuntLLMResponse:
    detection_logic: str
    confidence: float


class ILLMInferencePort(Protocol):
    async def generate(self, prompt: HuntLLMPrompt, tenant_id: UUID) -> HuntLLMResponse: ...
''',
    )
    w(
        base / "application" / "exceptions.py",
        '''from __future__ import annotations


class ApplicationError(Exception):
    pass


class ApplicationNotFoundError(ApplicationError):
    pass


class ApplicationForbiddenError(ApplicationError):
    pass
''',
    )
    w(
        base / "application" / "_auth.py",
        '''from __future__ import annotations

from threat_hunt.application.exceptions import ApplicationForbiddenError


def require_any(roles: tuple[str, ...], *allowed: str) -> None:
    if not any(r in roles for r in allowed):
        raise ApplicationForbiddenError(",".join(allowed))
''',
    )
    w(
        base / "application" / "commands" / "hunt_commands.py",
        '''from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class GenerateThreatHuntCandidate:
    tenant_id: UUID
    anomaly_signal_ids: tuple[str, ...]
    technique_ids: tuple[str, ...]
    detection_logic_draft: str
    confidence_score: float
    roles: tuple[str, ...]
    detection_rule_format: str = "sigma"


@dataclass(frozen=True, slots=True)
class PromoteThreatHuntCandidate:
    tenant_id: UUID
    candidate_id: UUID
    promoted_by: str
    promoted_rule_version_id: UUID
    roles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RejectThreatHuntCandidate:
    tenant_id: UUID
    candidate_id: UUID
    rejected_by: str
    rejection_reason: str
    roles: tuple[str, ...]
''',
    )
    w(
        base / "application" / "dtos" / "hunt_dtos.py",
        '''from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ThreatHuntCandidateDTO:
    candidate_id: str
    tenant_id: str
    status: str
    confidence_score: float
    detection_rule_format: str
    technique_coverage: list[str]
    anomaly_signal_count: int
''',
    )
    w(
        base / "application" / "services" / "hunt_application_service.py",
        '''from __future__ import annotations

from typing import Any
from uuid import UUID

from threat_hunt.application._auth import require_any
from threat_hunt.application.commands.hunt_commands import (
    GenerateThreatHuntCandidate,
    PromoteThreatHuntCandidate,
    RejectThreatHuntCandidate,
)
from threat_hunt.application.dtos.hunt_dtos import ThreatHuntCandidateDTO
from threat_hunt.application.exceptions import ApplicationNotFoundError
from threat_hunt.domain.services.candidate_generation_service import CandidateGenerationService
from threat_hunt.domain.services.candidate_review_service import CandidateReviewService
from threat_hunt.domain.value_objects.enums import DetectionRuleFormat
from threat_hunt.domain.value_objects.identifiers import (
    AnomalySignalRef,
    AttckTechniqueRef,
    TenantId,
)


class HuntApplicationService:
    def __init__(self, candidates: Any, configs: Any, event_sink: list[Any] | None = None) -> None:
        self._candidates = candidates
        self._configs = configs
        self._events: list[Any] = event_sink if event_sink is not None else []
        self._gen = CandidateGenerationService()
        self._review = CandidateReviewService()

    def _tenant(self, value: UUID) -> TenantId:
        return TenantId(value)

    def _dto(self, c: Any) -> ThreatHuntCandidateDTO:
        return ThreatHuntCandidateDTO(
            str(c.candidate_id),
            str(c.tenant_id),
            c.candidate_status.value,
            c.confidence_score,
            c.detection_rule_format.value,
            [t.technique_id for t in c.technique_coverage],
            len(c.anomaly_signal_refs),
        )

    async def generate(self, cmd: GenerateThreatHuntCandidate) -> ThreatHuntCandidateDTO:
        require_any(cmd.roles, "ai:operator", "system", "soc:detection_engineer")
        tenant = self._tenant(cmd.tenant_id)
        await self._configs.get_or_create_default(tenant)
        signals = tuple(AnomalySignalRef(s, "analytics") for s in cmd.anomaly_signal_ids)
        techniques = tuple(AttckTechniqueRef(t, t) for t in cmd.technique_ids)
        candidate = self._gen.create(
            tenant,
            signals,
            techniques,
            cmd.detection_logic_draft,
            cmd.confidence_score,
            DetectionRuleFormat(cmd.detection_rule_format),
        )
        await self._candidates.save(candidate, tenant)
        self._events.extend(candidate.pop_events())
        return self._dto(candidate)

    async def promote(self, cmd: PromoteThreatHuntCandidate) -> ThreatHuntCandidateDTO:
        tenant = self._tenant(cmd.tenant_id)
        candidate = await self._candidates.find_by_id(cmd.candidate_id, tenant)
        if candidate is None:
            raise ApplicationNotFoundError("candidate not found")
        self._review.promote(
            candidate, tenant, cmd.promoted_by, cmd.roles, cmd.promoted_rule_version_id
        )
        await self._candidates.save(candidate, tenant)
        self._events.extend(candidate.pop_events())
        return self._dto(candidate)

    async def reject(self, cmd: RejectThreatHuntCandidate) -> ThreatHuntCandidateDTO:
        tenant = self._tenant(cmd.tenant_id)
        candidate = await self._candidates.find_by_id(cmd.candidate_id, tenant)
        if candidate is None:
            raise ApplicationNotFoundError("candidate not found")
        self._review.reject(
            candidate, tenant, cmd.rejected_by, cmd.rejection_reason, cmd.roles
        )
        await self._candidates.save(candidate, tenant)
        self._events.extend(candidate.pop_events())
        return self._dto(candidate)

    async def queue(self, tenant_id: UUID, roles: tuple[str, ...], limit: int = 50) -> list[ThreatHuntCandidateDTO]:
        require_any(roles, "soc:detection_engineer", "ai:operator")
        rows = await self._candidates.find_pending_review(self._tenant(tenant_id), limit)
        return [self._dto(r) for r in rows]
''',
    )
    w(
        base / "infrastructure" / "persistence" / "in_memory_repositories.py",
        '''from __future__ import annotations

from uuid import UUID

from threat_hunt.domain.aggregates.threat_hunt_candidate import ThreatHuntCandidate
from threat_hunt.domain.aggregates.threat_hunt_configuration import ThreatHuntConfiguration
from threat_hunt.domain.repositories.i_repositories import (
    IThreatHuntCandidateRepository,
    IThreatHuntConfigurationRepository,
)
from threat_hunt.domain.value_objects.enums import ThreatHuntCandidateStatus
from threat_hunt.domain.value_objects.identifiers import TenantId


class InMemoryThreatHuntCandidateRepository(IThreatHuntCandidateRepository):
    def __init__(self) -> None:
        self._items: dict[str, dict[str, ThreatHuntCandidate]] = {}

    async def save(self, candidate: ThreatHuntCandidate, tenant_id: TenantId) -> None:
        self._items.setdefault(str(tenant_id), {})[str(candidate.candidate_id)] = candidate

    async def find_pending_review(
        self, tenant_id: TenantId, limit: int
    ) -> list[ThreatHuntCandidate]:
        rows = [
            c
            for c in self._items.get(str(tenant_id), {}).values()
            if c.candidate_status
            in {ThreatHuntCandidateStatus.CANDIDATE, ThreatHuntCandidateStatus.UNDER_REVIEW}
        ]
        return rows[:limit]

    async def find_by_id(
        self, candidate_id: UUID, tenant_id: TenantId
    ) -> ThreatHuntCandidate | None:
        return self._items.get(str(tenant_id), {}).get(str(candidate_id))


class InMemoryThreatHuntConfigurationRepository(IThreatHuntConfigurationRepository):
    def __init__(self) -> None:
        self._items: dict[str, ThreatHuntConfiguration] = {}

    async def get_or_create_default(self, tenant_id: TenantId) -> ThreatHuntConfiguration:
        key = str(tenant_id)
        if key not in self._items:
            self._items[key] = ThreatHuntConfiguration.default(tenant_id)
        return self._items[key]
''',
    )
    w(
        base / "infrastructure" / "llm" / "in_memory_llm.py",
        '''from __future__ import annotations

from uuid import UUID

from threat_hunt.application.ports.i_llm_inference_port import HuntLLMPrompt, HuntLLMResponse
from threat_hunt.domain.exceptions.domain_exceptions import TenantIsolationViolation


class InMemoryHuntLLMAdapter:
    async def generate(self, prompt: HuntLLMPrompt, tenant_id: UUID) -> HuntLLMResponse:
        if prompt.tenant_id != tenant_id:
            raise TenantIsolationViolation("hunt llm tenant mismatch")
        return HuntLLMResponse(detection_logic="selection: true", confidence=0.8)
''',
    )
    w(
        base / "infrastructure" / "acl" / "m33_anomaly_translator.py",
        '''from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AnomalySignalDetectedPayload:
    tenant_id: str
    signal_id: str
    strength: float
    technique_id: str | None = None


@dataclass(frozen=True, slots=True)
class ThreatHuntAnomalySignal:
    tenant_id: str
    signal_id: str
    strength: float
    technique_id: str | None


class M33AnomalyTranslator:
    def translate(self, payload: AnomalySignalDetectedPayload) -> ThreatHuntAnomalySignal | None:
        try:
            return ThreatHuntAnomalySignal(
                payload.tenant_id, payload.signal_id, payload.strength, payload.technique_id
            )
        except Exception:  # noqa: BLE001
            return None
''',
    )
    w(
        base / "infrastructure" / "workers" / "hunt_workers.py",
        '''from __future__ import annotations

from typing import Any
from uuid import UUID

from threat_hunt.application.commands.hunt_commands import GenerateThreatHuntCandidate


class ThreatHuntCandidateWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.processed = 0

    async def handle(
        self,
        tenant_id: UUID,
        signal_ids: tuple[str, ...],
        technique_ids: tuple[str, ...] = ("T1059",),
    ) -> Any:
        self.processed += 1
        return await self._app.generate(
            GenerateThreatHuntCandidate(
                tenant_id,
                signal_ids,
                technique_ids,
                "title: generated\\ndetection: selection",
                0.82,
                ("system",),
            )
        )


class HuntScheduler:
    def __init__(self, worker: ThreatHuntCandidateWorker) -> None:
        self.worker = worker

    async def tick(self, tenant_id: UUID) -> int:
        await self.worker.handle(tenant_id, ("sig-auto",))
        return self.worker.processed
''',
    )
    w(
        base / "infrastructure" / "container.py",
        '''from __future__ import annotations

from threat_hunt.application.services.hunt_application_service import HuntApplicationService
from threat_hunt.infrastructure.llm.in_memory_llm import InMemoryHuntLLMAdapter
from threat_hunt.infrastructure.persistence.in_memory_repositories import (
    InMemoryThreatHuntCandidateRepository,
    InMemoryThreatHuntConfigurationRepository,
)
from threat_hunt.infrastructure.workers.hunt_workers import HuntScheduler, ThreatHuntCandidateWorker


class ThreatHuntContainer:
    def __init__(self) -> None:
        self.candidates = InMemoryThreatHuntCandidateRepository()
        self.configs = InMemoryThreatHuntConfigurationRepository()
        self.llm = InMemoryHuntLLMAdapter()
        self.event_sink: list[object] = []
        self.app = HuntApplicationService(self.candidates, self.configs, self.event_sink)
        self.candidate_worker = ThreatHuntCandidateWorker(self.app)
        self.scheduler = HuntScheduler(self.candidate_worker)
''',
    )
    w(
        base / "api" / "dependencies.py",
        '''from __future__ import annotations

from uuid import UUID

from fastapi import Header, Request

from threat_hunt.infrastructure.container import ThreatHuntContainer


def get_container(request: Request) -> ThreatHuntContainer:
    c = getattr(request.app.state, "threat_hunt_container", None)
    if c is None:
        c = ThreatHuntContainer()
        request.app.state.threat_hunt_container = c
    return c


def tenant_id_header(x_tenant_id: UUID = Header(..., alias="X-Tenant-Id")) -> UUID:
    return x_tenant_id


def roles_header(x_roles: str = Header("", alias="X-Roles")) -> tuple[str, ...]:
    return tuple(r.strip() for r in x_roles.split(",") if r.strip())
''',
    )
    w(
        base / "api" / "v1" / "__init__.py",
        "from threat_hunt.api.v1.routes import router\n\n__all__ = ['router']\n",
    )
    w(
        base / "api" / "v1" / "routes.py",
        '''from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from threat_hunt.api.dependencies import get_container, roles_header, tenant_id_header
from threat_hunt.application.commands.hunt_commands import (
    GenerateThreatHuntCandidate,
    PromoteThreatHuntCandidate,
    RejectThreatHuntCandidate,
)
from threat_hunt.application.exceptions import ApplicationForbiddenError, ApplicationNotFoundError
from threat_hunt.domain.exceptions.domain_exceptions import ThreatHuntDomainError
from threat_hunt.infrastructure.container import ThreatHuntContainer

router = APIRouter(prefix="/threat-hunt", tags=["threat-hunt"])


def _map(exc: Exception) -> HTTPException:
    if isinstance(exc, ApplicationForbiddenError):
        return HTTPException(status_code=403, detail=str(exc))
    if isinstance(exc, ApplicationNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, ThreatHuntDomainError):
        return HTTPException(status_code=409, detail=str(exc))
    return HTTPException(status_code=400, detail=str(exc))


class GenerateBody(BaseModel):
    anomaly_signal_ids: list[str]
    technique_ids: list[str] = Field(default_factory=lambda: ["T1059"])
    detection_logic_draft: str = "title: draft"
    confidence_score: float = 0.8
    detection_rule_format: str = "sigma"


class PromoteBody(BaseModel):
    promoted_by: str
    promoted_rule_version_id: UUID


class RejectBody(BaseModel):
    rejected_by: str
    rejection_reason: str


@router.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "context": "threat_hunt"}


@router.get("/candidates")
async def list_candidates(
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: ThreatHuntContainer = Depends(get_container),
) -> list[dict[str, Any]]:
    try:
        return [asdict(r) for r in await container.app.queue(tenant_id, roles)]
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/candidates", status_code=201)
async def generate(
    body: GenerateBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: ThreatHuntContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.generate(
            GenerateThreatHuntCandidate(
                tenant_id,
                tuple(body.anomaly_signal_ids),
                tuple(body.technique_ids),
                body.detection_logic_draft,
                body.confidence_score,
                roles,
                body.detection_rule_format,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/candidates/{candidate_id}/promote")
async def promote(
    candidate_id: UUID,
    body: PromoteBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: ThreatHuntContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.promote(
            PromoteThreatHuntCandidate(
                tenant_id,
                candidate_id,
                body.promoted_by,
                body.promoted_rule_version_id,
                roles,
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc


@router.post("/candidates/{candidate_id}/reject")
async def reject(
    candidate_id: UUID,
    body: RejectBody,
    tenant_id: UUID = Depends(tenant_id_header),
    roles: tuple[str, ...] = Depends(roles_header),
    container: ThreatHuntContainer = Depends(get_container),
) -> dict[str, Any]:
    try:
        dto = await container.app.reject(
            RejectThreatHuntCandidate(
                tenant_id, candidate_id, body.rejected_by, body.rejection_reason, roles
            )
        )
        return asdict(dto)
    except Exception as exc:
        raise _map(exc) from exc
''',
    )
    tbase = TESTS / "threat_hunt"
    w(tbase / "__init__.py", "")
    w(
        tbase / "test_architecture.py",
        '''from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "threat_hunt"


def test_layout() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "py.typed").is_file()


def test_no_upstream_domain_imports() -> None:
    bad = re.compile(r"from (detection|campaign|playbook|autonomous_intelligence|posture_forecasting)\\.")
    for p in ROOT.rglob("*.py"):
        if "infrastructure/acl" in str(p):
            continue
        if bad.search(p.read_text()):
            raise AssertionError(p)
''',
    )
    w(
        tbase / "test_lifecycle.py",
        '''from __future__ import annotations

from uuid import UUID, uuid4

import pytest

from threat_hunt.application.commands.hunt_commands import (
    GenerateThreatHuntCandidate,
    PromoteThreatHuntCandidate,
    RejectThreatHuntCandidate,
)
from threat_hunt.domain.exceptions.domain_exceptions import AuthorizationDenied
from threat_hunt.infrastructure.container import ThreatHuntContainer


@pytest.mark.asyncio
async def test_generate_and_promote() -> None:
    c = ThreatHuntContainer()
    tenant = uuid4()
    created = await c.app.generate(
        GenerateThreatHuntCandidate(
            tenant, ("s1",), ("T1059",), "logic", 0.9, ("system",)
        )
    )
    assert created.status == "candidate"
    promoted = await c.app.promote(
        PromoteThreatHuntCandidate(
            tenant,
            UUID(created.candidate_id),
            "eng",
            uuid4(),
            ("soc:detection_engineer",),
        )
    )
    assert promoted.status == "promoted"
    assert promoted.anomaly_signal_count == 1


@pytest.mark.asyncio
async def test_promote_requires_role() -> None:
    c = ThreatHuntContainer()
    tenant = uuid4()
    created = await c.app.generate(
        GenerateThreatHuntCandidate(
            tenant, ("s1",), ("T1059",), "logic", 0.9, ("system",)
        )
    )
    with pytest.raises(AuthorizationDenied):
        await c.app.promote(
            PromoteThreatHuntCandidate(
                tenant, UUID(created.candidate_id), "x", uuid4(), ("ai:operator",)
            )
        )


@pytest.mark.asyncio
async def test_reject() -> None:
    c = ThreatHuntContainer()
    tenant = uuid4()
    created = await c.app.generate(
        GenerateThreatHuntCandidate(
            tenant, ("s1",), ("T1059",), "logic", 0.9, ("system",)
        )
    )
    rejected = await c.app.reject(
        RejectThreatHuntCandidate(
            tenant,
            UUID(created.candidate_id),
            "eng",
            "noise",
            ("soc:detection_engineer",),
        )
    )
    assert rejected.status == "rejected"
''',
    )
    w(
        tbase / "test_api.py",
        '''from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from threat_hunt.api.v1.routes import router
from threat_hunt.infrastructure.container import ThreatHuntContainer


@pytest.mark.asyncio
async def test_candidates_api() -> None:
    app = FastAPI()
    app.include_router(router)
    app.state.threat_hunt_container = ThreatHuntContainer()
    headers = {"X-Tenant-Id": str(uuid4()), "X-Roles": "system,soc:detection_engineer"}
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/threat-hunt/candidates",
            json={"anomaly_signal_ids": ["a1"], "technique_ids": ["T1059"]},
            headers=headers,
        )
        assert r.status_code == 201
        q = await client.get("/threat-hunt/candidates", headers=headers)
        assert len(q.json()) == 1
''',
    )
    w(
        tbase / "test_bulk.py",
        '''from __future__ import annotations

from uuid import uuid4

import pytest

from threat_hunt.domain.value_objects.enums import DetectionRuleFormat, ThreatHuntCandidateStatus
from threat_hunt.infrastructure.acl.m33_anomaly_translator import (
    AnomalySignalDetectedPayload,
    M33AnomalyTranslator,
)
from threat_hunt.infrastructure.container import ThreatHuntContainer
from threat_hunt.infrastructure.llm.in_memory_llm import InMemoryHuntLLMAdapter
from threat_hunt.application.ports.i_llm_inference_port import HuntLLMPrompt
from threat_hunt.domain.exceptions.domain_exceptions import TenantIsolationViolation


@pytest.mark.parametrize("status", list(ThreatHuntCandidateStatus))
def test_statuses(status: ThreatHuntCandidateStatus) -> None:
    assert isinstance(status.value, str)


@pytest.mark.parametrize("fmt", list(DetectionRuleFormat))
def test_formats(fmt: DetectionRuleFormat) -> None:
    assert fmt.value == fmt.name.lower()


def test_acl() -> None:
    sig = M33AnomalyTranslator().translate(
        AnomalySignalDetectedPayload("t", "s1", 0.9, "T1059")
    )
    assert sig is not None


@pytest.mark.asyncio
async def test_llm_tenant_isolation() -> None:
    llm = InMemoryHuntLLMAdapter()
    t = uuid4()
    with pytest.raises(TenantIsolationViolation):
        await llm.generate(HuntLLMPrompt(t, "task", "ctx"), uuid4())


@pytest.mark.asyncio
async def test_scheduler() -> None:
    c = ThreatHuntContainer()
    n = await c.scheduler.tick(uuid4())
    assert n == 1
''',
    )
