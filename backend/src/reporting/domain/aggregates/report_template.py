"""ReportTemplate aggregate — structure and section definitions."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from reporting.domain.value_objects.enums import ReportType

if TYPE_CHECKING:
    from datetime import datetime

    from reporting.domain.value_objects.identifiers import ReportTemplateId, TenantId


class ReportTemplate:
    __slots__ = (
        "created_at",
        "name",
        "report_type",
        "sections",
        "template_id",
        "tenant_id",
        "version",
    )

    def __init__(
        self,
        template_id: ReportTemplateId,
        report_type: ReportType,
        name: str,
        sections: list[str],
        version: int,
        created_at: datetime,
        tenant_id: TenantId | None = None,
    ) -> None:
        self.template_id = template_id
        self.report_type = report_type
        self.name = name
        self.sections = list(sections)
        self.version = version
        self.created_at = created_at
        self.tenant_id = tenant_id

    @classmethod
    def create_platform(
        cls,
        template_id: ReportTemplateId,
        report_type: ReportType,
        name: str,
        sections: list[str],
        at: datetime,
        *,
        version: int = 1,
    ) -> ReportTemplate:
        return cls(template_id, report_type, name, sections, version, at, tenant_id=None)

    def to_definition(self) -> dict[str, Any]:
        return {
            "template_id": str(self.template_id),
            "report_type": self.report_type.value,
            "name": self.name,
            "sections": list(self.sections),
            "version": self.version,
        }
