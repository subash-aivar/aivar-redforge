"""SchemaVersion — semantic (major.minor) CEM versioning (M37 §2.3).

Normalizers declare which CEM major version they emit. Major bumps are
breaking (require a new normalizer version and a defined migration/
backfill strategy at the storage layer); minor bumps are additive-only
within `attributes`. Every stored event retains its `schema_version`
permanently — reprocessing/backfill is a projection concern, never a
mutation of stored events.
"""

from __future__ import annotations

from dataclasses import dataclass

from siem_shared.domain.exceptions.domain_exceptions import InvalidSchemaVersionStringError


@dataclass(frozen=True, slots=True, order=True)
class SchemaVersion:
    major: int
    minor: int

    def __post_init__(self) -> None:
        if self.major < 0 or self.minor < 0:
            raise ValueError("SchemaVersion.major and .minor must be non-negative")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}"

    @classmethod
    def parse(cls, raw: str) -> SchemaVersion:
        parts = raw.split(".")
        if len(parts) != 2:
            raise InvalidSchemaVersionStringError(raw)
        try:
            major, minor = int(parts[0]), int(parts[1])
        except ValueError as exc:
            raise InvalidSchemaVersionStringError(raw) from exc
        return cls(major=major, minor=minor)

    def is_compatible_with(self, other: SchemaVersion) -> bool:
        """Backward compatibility per M37 §2.3: two versions are
        compatible (a consumer built for `other` can read `self`) iff
        they share the same major version — minor bumps are additive-
        only, so a consumer never needs to reject a higher minor."""
        return self.major == other.major

    def is_breaking_change_from(self, other: SchemaVersion) -> bool:
        return self.major != other.major
