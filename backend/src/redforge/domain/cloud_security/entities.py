"""Non-root entities for CloudAccount aggregate."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AvailabilityZone:
    """AZ within a cloud region."""

    name: str
    region_code: str

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise ValueError("AvailabilityZone.name required")
        if not self.region_code or not self.region_code.strip():
            raise ValueError("AvailabilityZone.region_code required")
        if len(self.name) > 64 or len(self.region_code) > 64:
            raise ValueError("AvailabilityZone fields max 64 chars")

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "region_code": self.region_code}

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> AvailabilityZone:
        return cls(name=str(data["name"]), region_code=str(data["region_code"]))


@dataclass(frozen=True, slots=True)
class CloudRegion:
    """Enabled cloud region with optional endpoint metadata and AZs."""

    region_code: str
    display_name: str
    endpoint: str | None = None
    availability_zones: tuple[AvailabilityZone, ...] = ()

    def __post_init__(self) -> None:
        if not self.region_code or not self.region_code.strip():
            raise ValueError("CloudRegion.region_code required")
        if not self.display_name or not self.display_name.strip():
            raise ValueError("CloudRegion.display_name required")
        if len(self.region_code) > 64:
            raise ValueError("region_code max 64 chars")
        if len(self.display_name) > 256:
            raise ValueError("display_name max 256 chars")
        if self.endpoint is not None and len(self.endpoint) > 512:
            raise ValueError("endpoint max 512 chars")
        for az in self.availability_zones:
            if az.region_code != self.region_code:
                raise ValueError("AvailabilityZone.region_code must match CloudRegion")

    def to_dict(self) -> dict[str, object]:
        return {
            "region_code": self.region_code,
            "display_name": self.display_name,
            "endpoint": self.endpoint,
            "availability_zones": [az.to_dict() for az in self.availability_zones],
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> CloudRegion:
        az_raw = data.get("availability_zones") or []
        zones: list[AvailabilityZone] = []
        if isinstance(az_raw, list):
            for item in az_raw:
                if isinstance(item, dict):
                    zones.append(AvailabilityZone.from_dict(item))
        endpoint = data.get("endpoint")
        return cls(
            region_code=str(data["region_code"]),
            display_name=str(data["display_name"]),
            endpoint=str(endpoint) if endpoint is not None else None,
            availability_zones=tuple(zones),
        )
