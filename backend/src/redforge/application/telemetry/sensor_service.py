"""Telemetry sensor registration service — M18."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from ulid import ULID

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

_SUPPORTED_FORMATS = frozenset({"suricata_eve", "zeek_json"})


class UnknownFormatError(ValueError):
    pass


class SensorAlreadyExistsError(ValueError):
    pass


class TelemetrySensorService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def register_sensor(
        self,
        organization_id: str,
        created_by: str,
        name: str,
        format: str,
        description: str = "",
        token_ref: str | None = None,
    ) -> str:
        """Register a new telemetry sensor. Returns the new sensor ID.
        Raises UnknownFormatError for unsupported formats.
        Raises SensorAlreadyExistsError if the name is already taken for this org."""
        if format not in _SUPPORTED_FORMATS:
            raise UnknownFormatError(
                f"Unsupported format {format!r}. Supported: {sorted(_SUPPORTED_FORMATS)}"
            )
        from redforge.infrastructure.database.models.telemetry import TelemetrySensorModel
        from redforge.infrastructure.database.repositories.telemetry_repository import (
            SqlAlchemyTelemetrySensorRepository,
        )

        repo = SqlAlchemyTelemetrySensorRepository(self._session)
        existing = await repo.get_by_name(organization_id, name)
        if existing is not None:
            raise SensorAlreadyExistsError(f"sensor {name!r} already registered for this org")

        now = datetime.now(UTC)
        sensor = TelemetrySensorModel(
            id=str(ULID()),
            organization_id=organization_id,
            name=name,
            format=format,
            description=description,
            token_ref=token_ref,
            enabled=True,
            created_by=created_by,
            created_at=now,
            updated_at=now,
        )
        await repo.create(sensor)
        return sensor.id

    async def remove_sensor(
        self,
        organization_id: str,
        sensor_id: str,
    ) -> bool:
        from redforge.infrastructure.database.repositories.telemetry_repository import (
            SqlAlchemyTelemetrySensorRepository,
        )

        repo = SqlAlchemyTelemetrySensorRepository(self._session)
        return await repo.delete(organization_id, sensor_id)
