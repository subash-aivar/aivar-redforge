"""Resolve CSPM ComplianceRef pointers against the M24 control catalog."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Protocol

from redforge.domain.cloud_security.cspm.value_objects import ComplianceRef
from redforge.domain.compliance.value_objects import FrameworkKey

if TYPE_CHECKING:
    from redforge.application.compliance.mapping_service import CatalogQueryService
    from redforge.domain.compliance.repository import ControlCatalogRepository

logger = logging.getLogger(__name__)


class _CatalogPort(Protocol):
    async def get_framework(self, key: FrameworkKey) -> object | None: ...

    async def list_requirements(
        self,
        framework_key: FrameworkKey,
        *,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list[object], int]: ...


class CSPMComplianceACL:
    """Marks ComplianceRef.resolved based on catalog presence."""

    def __init__(
        self,
        catalog: CatalogQueryService | ControlCatalogRepository | _CatalogPort | None = None,
    ) -> None:
        self._catalog = catalog

    async def resolve_refs(self, refs: list[ComplianceRef]) -> list[ComplianceRef]:
        if not refs:
            return []
        if self._catalog is None:
            return [
                ComplianceRef(
                    framework_key=r.framework_key,
                    requirement_ref=r.requirement_ref,
                    resolved=False,
                )
                for r in refs
            ]
        out: list[ComplianceRef] = []
        for ref in refs:
            resolved = await self._is_resolved(ref)
            out.append(
                ComplianceRef(
                    framework_key=ref.framework_key,
                    requirement_ref=ref.requirement_ref,
                    resolved=resolved,
                )
            )
        return out

    async def _is_resolved(self, ref: ComplianceRef) -> bool:
        try:
            key = FrameworkKey(ref.framework_key)
        except ValueError:
            return False
        try:
            framework = await self._catalog.get_framework(key)  # type: ignore[union-attr]
            if framework is not None:
                getter = getattr(framework, "get_requirement_by_ref", None)
                if callable(getter):
                    try:
                        getter(ref.requirement_ref)
                        return True
                    except Exception:
                        pass
                    requirements = getattr(framework, "requirements", None)
                    if isinstance(requirements, dict):
                        for req in requirements.values():
                            if getattr(req, "requirement_ref", None) == ref.requirement_ref:
                                return True
            if hasattr(self._catalog, "list_requirements"):
                items, _total = await self._catalog.list_requirements(  # type: ignore[union-attr]
                    key, search=ref.requirement_ref, limit=50, offset=0
                )
                for item in items:
                    if getattr(item, "requirement_ref", None) == ref.requirement_ref:
                        return True
        except Exception:
            logger.debug(
                "cspm_compliance: resolve failed for %s/%s",
                ref.framework_key,
                ref.requirement_ref,
                exc_info=True,
            )
            return False
        return False
