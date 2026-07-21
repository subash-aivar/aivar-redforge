"""Dependency injection container for evaluation context."""

from __future__ import annotations

from typing import TYPE_CHECKING

from evaluation.infrastructure.acl.degraded_adapters import (
    StubAttackActionQueryAdapter,
    StubComplianceQueryAdapter,
    StubDetectionFindingQueryAdapter,
    StubEvidenceQueryAdapter,
    StubSecurityGraphWriteAdapter,
)
from evaluation.infrastructure.events.structlog_event_publisher import (
    StructlogEventPublisher,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from sqlalchemy.ext.asyncio import AsyncSession

    from evaluation.application.ports.i_event_publisher import IEventPublisher
    from evaluation.application.services.evaluation_application_service import (
        EvaluationApplicationService,
    )
    from evaluation.domain.ports.i_attack_action_query_port import IAttackActionQueryPort
    from evaluation.domain.ports.i_compliance_query_port import IComplianceQueryPort
    from evaluation.domain.ports.i_detection_finding_query_port import IDetectionFindingQueryPort
    from evaluation.domain.ports.i_evidence_query_port import IEvidenceQueryPort
    from evaluation.domain.ports.i_security_graph_write_port import ISecurityGraphWritePort
    from evaluation.infrastructure.persistence.unit_of_work import PgUnitOfWork


def build_evaluation_application_service(
    session_factory: Callable[[], AsyncSession],
    attack_action_port: IAttackActionQueryPort | None = None,
    detection_finding_port: IDetectionFindingQueryPort | None = None,
    evidence_port: IEvidenceQueryPort | None = None,
    compliance_port: IComplianceQueryPort | None = None,
    graph_write_port: ISecurityGraphWritePort | None = None,
    event_publisher: IEventPublisher | None = None,
    *,
    bridge_projections: bool = False,
) -> EvaluationApplicationService:
    from evaluation.application.services.evaluation_application_service import (
        EvaluationApplicationService,
    )
    from evaluation.infrastructure.persistence.unit_of_work import PgUnitOfWork

    def uow_factory() -> PgUnitOfWork:
        return PgUnitOfWork(session_factory())

    publisher: IEventPublisher
    if event_publisher is not None:
        publisher = event_publisher
    elif bridge_projections:
        from evaluation.application.projections.evaluation_read_models import (
            DetectionCoverageTrendProjection,
            KillChainProgressionProjection,
            ObjectiveHistoryProjection,
            TechniqueSuccessRateProjection,
        )
        from evaluation.infrastructure.events.projection_bridging_publisher import (
            ProjectionBridgingEventPublisher,
        )

        bridging = ProjectionBridgingEventPublisher()
        bridging.register_projection(DetectionCoverageTrendProjection())
        bridging.register_projection(TechniqueSuccessRateProjection())
        bridging.register_projection(KillChainProgressionProjection())
        bridging.register_projection(ObjectiveHistoryProjection())
        publisher = bridging
    else:
        publisher = StructlogEventPublisher()

    return EvaluationApplicationService(
        uow_factory=uow_factory,
        event_publisher=publisher,
        attack_action_port=attack_action_port or StubAttackActionQueryAdapter(),
        detection_finding_port=(detection_finding_port or StubDetectionFindingQueryAdapter()),
        evidence_port=evidence_port or StubEvidenceQueryAdapter(),
        compliance_port=compliance_port or StubComplianceQueryAdapter(),
        graph_write_port=graph_write_port or StubSecurityGraphWriteAdapter(),
    )
