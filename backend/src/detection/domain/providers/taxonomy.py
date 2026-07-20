"""Normalized telemetry field taxonomy and registry."""

from __future__ import annotations

from dataclasses import dataclass

from detection.domain.exceptions.domain_exceptions import InvalidArgument
from detection.domain.value_objects.enums import FieldDataType
from detection.domain.value_objects.rule_logic import NormalizedFieldRef

# Top-level namespaces from M28 Architecture Freeze §6.3
TELEMETRY_NAMESPACES: frozenset[str] = frozenset(
    {
        "event",
        "actor",
        "target",
        "action",
        "network",
        "process",
        "file",
        "cloud",
        "container",
        "identity",
    }
)

# Canonical fields per namespace (platform-owned taxonomy)
_TAXONOMY_FIELDS: dict[str, tuple[tuple[str, FieldDataType], ...]] = {
    "event": (
        ("event_type", FieldDataType.STRING),
        ("event_time", FieldDataType.TIMESTAMP),
        ("event_source", FieldDataType.STRING),
        ("event_id", FieldDataType.STRING),
    ),
    "actor": (
        ("user_id", FieldDataType.STRING),
        ("user_name", FieldDataType.STRING),
        ("user_type", FieldDataType.STRING),
        ("service_account", FieldDataType.BOOLEAN),
        ("ip_address", FieldDataType.IP),
        ("geo", FieldDataType.STRING),
    ),
    "target": (
        ("resource_id", FieldDataType.STRING),
        ("resource_type", FieldDataType.STRING),
        ("resource_name", FieldDataType.STRING),
        ("asset_ref", FieldDataType.STRING),
    ),
    "action": (
        ("action_type", FieldDataType.STRING),
        ("action_result", FieldDataType.STRING),
        ("action_parameters", FieldDataType.OBJECT),
    ),
    "network": (
        ("src_ip", FieldDataType.IP),
        ("dst_ip", FieldDataType.IP),
        ("src_port", FieldDataType.INTEGER),
        ("dst_port", FieldDataType.INTEGER),
        ("protocol", FieldDataType.STRING),
        ("bytes_transferred", FieldDataType.INTEGER),
    ),
    "process": (
        ("pid", FieldDataType.INTEGER),
        ("name", FieldDataType.STRING),
        ("command_line", FieldDataType.STRING),
        ("parent_pid", FieldDataType.INTEGER),
        ("parent_name", FieldDataType.STRING),
        ("hash", FieldDataType.STRING),
    ),
    "file": (
        ("path", FieldDataType.STRING),
        ("name", FieldDataType.STRING),
        ("hash", FieldDataType.STRING),
        ("size", FieldDataType.INTEGER),
        ("permissions", FieldDataType.STRING),
    ),
    "cloud": (
        ("provider", FieldDataType.STRING),
        ("region", FieldDataType.STRING),
        ("account_id", FieldDataType.STRING),
        ("service", FieldDataType.STRING),
        ("api_call", FieldDataType.STRING),
    ),
    "container": (
        ("image", FieldDataType.STRING),
        ("image_digest", FieldDataType.STRING),
        ("container_id", FieldDataType.STRING),
        ("namespace", FieldDataType.STRING),
        ("pod_name", FieldDataType.STRING),
    ),
    "identity": (
        ("identity_type", FieldDataType.STRING),
        ("privilege_level", FieldDataType.STRING),
        ("auth_method", FieldDataType.STRING),
        ("mfa_used", FieldDataType.BOOLEAN),
    ),
}


@dataclass(frozen=True, slots=True)
class TaxonomyField:
    path: str
    namespace: str
    name: str
    data_type: FieldDataType


class NormalizedFieldRegistry:
    """Platform-owned registry of normalized field paths."""

    def __init__(self) -> None:
        self._fields: dict[str, TaxonomyField] = {}
        for namespace, entries in _TAXONOMY_FIELDS.items():
            for name, dtype in entries:
                path = f"{namespace}.{name}"
                self._fields[path] = TaxonomyField(
                    path=path,
                    namespace=namespace,
                    name=name,
                    data_type=dtype,
                )

    def namespaces(self) -> frozenset[str]:
        return TELEMETRY_NAMESPACES

    def all_paths(self) -> frozenset[str]:
        return frozenset(self._fields.keys())

    def get(self, path: str) -> TaxonomyField | None:
        return self._fields.get(path.strip())

    def contains(self, path: str) -> bool:
        return path.strip() in self._fields

    def validate_path(self, path: str) -> NormalizedFieldRef:
        cleaned = path.strip()
        if "." not in cleaned:
            raise InvalidArgument(
                "NormalizedFieldRef",
                f"must be namespaced (got {cleaned!r})",
            )
        namespace, _, _name = cleaned.partition(".")
        if namespace not in TELEMETRY_NAMESPACES:
            raise InvalidArgument(
                "NormalizedFieldRef",
                f"unknown namespace {namespace!r}; "
                f"allowed: {', '.join(sorted(TELEMETRY_NAMESPACES))}",
            )
        if cleaned not in self._fields:
            raise InvalidArgument(
                "NormalizedFieldRef",
                f"unknown field {cleaned!r} in taxonomy",
            )
        return NormalizedFieldRef(cleaned)

    def fields_for_namespace(self, namespace: str) -> list[TaxonomyField]:
        if namespace not in TELEMETRY_NAMESPACES:
            raise InvalidArgument("namespace", f"unknown: {namespace}")
        return [f for f in self._fields.values() if f.namespace == namespace]


# Module-level singleton used by validation / schema helpers
FIELD_REGISTRY = NormalizedFieldRegistry()
