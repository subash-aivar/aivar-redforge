from __future__ import annotations

from typing import TYPE_CHECKING

from ml_pipeline.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort

if TYPE_CHECKING:
    from uuid import UUID


class SecurityGraphWriteAdapter(ISecurityGraphWritePort):
    """Append-only predictive risk nodes. NO writes to vulnerability/exposure aggregates."""

    FORBIDDEN_KINDS = frozenset({"vulnerability", "exposure", "ExposureRecord"})

    def __init__(self) -> None:
        self.nodes: list[dict[str, object]] = []

    async def upsert_predictive_risk_node(
        self,
        tenant_id: UUID,
        *,
        model_id: UUID,
        asset_ref_id: UUID,
        score: float,
        signal_type: str,
    ) -> None:
        kind = "predictive_risk"
        if kind in self.FORBIDDEN_KINDS:
            raise RuntimeError("refusing forbidden graph write")
        self.nodes.append(
            {
                "tenant_id": str(tenant_id),
                "model_id": str(model_id),
                "asset_ref_id": str(asset_ref_id),
                "score": score,
                "signal_type": signal_type,
                "kind": kind,
                "advisory_only": True,
            }
        )


# Back-compat alias
InMemorySecurityGraphWriteAdapter = SecurityGraphWriteAdapter
