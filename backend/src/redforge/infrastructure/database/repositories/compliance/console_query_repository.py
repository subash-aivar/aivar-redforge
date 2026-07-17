"""Read-model repository for Compliance Operations Console queries (M24 Phase 4).

Additive SQL aggregations and paginated lists. Does not mutate domain aggregates.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from sqlalchemy import Integer, cast, func, select, text

from redforge.infrastructure.database.models.compliance import (
    AssessmentPeriodModel,
    ComplianceProfileModel,
    ControlAssessmentModel,
    EvidenceRecommendationModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

SortDir = Literal["asc", "desc"]


class SqlAlchemyComplianceConsoleQueryRepository:
    """Org-scoped read queries for the operations console."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def overview_summary(self, organization_id: str) -> dict[str, Any]:
        open_periods = await self._session.scalar(
            select(func.count())
            .select_from(AssessmentPeriodModel)
            .where(
                AssessmentPeriodModel.organization_id == organization_id,
                AssessmentPeriodModel.status == "open",
            )
        )
        profiles = await self._session.scalar(
            select(func.count())
            .select_from(ComplianceProfileModel)
            .where(ComplianceProfileModel.organization_id == organization_id)
        )
        assessment_total = await self._session.scalar(
            select(func.count())
            .select_from(ControlAssessmentModel)
            .where(ControlAssessmentModel.organization_id == organization_id)
        )
        status_rows = (
            await self._session.execute(
                select(ControlAssessmentModel.status, func.count())
                .where(ControlAssessmentModel.organization_id == organization_id)
                .group_by(ControlAssessmentModel.status)
            )
        ).all()
        status_counts = {str(s): int(c) for s, c in status_rows}
        validated = status_counts.get("technically_validated", 0)
        total_a = int(assessment_total or 0)

        # Posture score matches UI helper weights (presentation contract).
        weights = {
            "not_assessed": 0.0,
            "collecting_evidence": 0.35,
            "pending_confirmation": 0.65,
            "technically_validated": 1.0,
        }
        weighted = 0.0
        for status, count in status_counts.items():
            weighted += weights.get(status, 0.25) * count
        posture_score = 0 if total_a == 0 else round((weighted / total_a) * 100)
        band = (
            "strong"
            if posture_score >= 80
            else "moderate"
            if posture_score >= 55
            else "at_risk"
            if posture_score >= 30
            else "critical"
        )

        # Evidence link count via jsonb array length sum
        evidence_link_count = await self._session.scalar(
            select(
                func.coalesce(
                    func.sum(
                        func.jsonb_array_length(ControlAssessmentModel.evidence_links)
                    ),
                    0,
                )
            ).where(ControlAssessmentModel.organization_id == organization_id)
        )
        with_evidence = await self._session.scalar(
            select(func.count())
            .select_from(ControlAssessmentModel)
            .where(
                ControlAssessmentModel.organization_id == organization_id,
                func.jsonb_array_length(ControlAssessmentModel.evidence_links) > 0,
            )
        )

        rec_rows = (
            await self._session.execute(
                select(EvidenceRecommendationModel.status, func.count())
                .where(EvidenceRecommendationModel.organization_id == organization_id)
                .group_by(EvidenceRecommendationModel.status)
            )
        ).all()
        rec_counts = {
            "recommended": 0,
            "accepted": 0,
            "linked": 0,
            "rejected": 0,
        }
        for status, count in rec_rows:
            key = str(status)
            if key in rec_counts:
                rec_counts[key] = int(count)
        rec_total = sum(rec_counts.values())
        decided = (
            rec_counts["accepted"] + rec_counts["linked"] + rec_counts["rejected"]
        )
        acceptance_pct = (
            0
            if decided == 0
            else round(
                ((rec_counts["accepted"] + rec_counts["linked"]) / decided) * 100
            )
        )

        framework_rows = (
            await self._session.execute(
                select(
                    ControlAssessmentModel.framework_key,
                    func.count().label("total"),
                    func.sum(
                        cast(
                            ControlAssessmentModel.status == "technically_validated",
                            Integer,
                        )
                    ).label("validated"),
                )
                .where(ControlAssessmentModel.organization_id == organization_id)
                .group_by(ControlAssessmentModel.framework_key)
            )
        ).all()
        framework_progress = [
            {
                "framework_key": str(fw),
                "total": int(total or 0),
                "validated": int(validated_n or 0),
                "coverage_pct": (
                    0
                    if not total
                    else round((int(validated_n or 0) / int(total)) * 100)
                ),
            }
            for fw, total, validated_n in framework_rows
        ]

        recent_validated = (
            await self._session.scalars(
                select(ControlAssessmentModel)
                .where(
                    ControlAssessmentModel.organization_id == organization_id,
                    ControlAssessmentModel.status == "technically_validated",
                )
                .order_by(ControlAssessmentModel.updated_at.desc())
                .limit(8)
            )
        ).all()

        open_period_rows = (
            await self._session.scalars(
                select(AssessmentPeriodModel)
                .where(
                    AssessmentPeriodModel.organization_id == organization_id,
                    AssessmentPeriodModel.status == "open",
                )
                .order_by(AssessmentPeriodModel.period_start.desc())
                .limit(20)
            )
        ).all()

        return {
            "profiles": int(profiles or 0),
            "open_periods": int(open_periods or 0),
            "assessments_total": total_a,
            "validated_count": validated,
            "posture_score": posture_score,
            "posture_band": band,
            "status_counts": status_counts,
            "evidence_link_count": int(evidence_link_count or 0),
            "assessments_with_evidence": int(with_evidence or 0),
            "recommendation_counts": {**rec_counts, "total": rec_total},
            "acceptance_pct": acceptance_pct,
            "framework_progress": framework_progress,
            "open_period_summaries": [
                {
                    "id": row.id,
                    "name": row.name,
                    "framework_key": row.framework_key,
                    "period_start": row.period_start,
                    "period_end": row.period_end,
                    "status": row.status,
                }
                for row in open_period_rows
            ],
            "recently_validated": [
                {
                    "id": row.id,
                    "framework_key": row.framework_key,
                    "requirement_id": row.requirement_id,
                    "status": row.status,
                    "evidence_count": len(row.evidence_links or []),
                    "updated_at": row.updated_at,
                }
                for row in recent_validated
            ],
        }

    async def list_assessments_page(
        self,
        organization_id: str,
        *,
        period_id: str | None = None,
        status: str | None = None,
        framework_key: str | None = None,
        search: str | None = None,
        sort: str = "updated_at",
        sort_dir: SortDir = "desc",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        filters = [ControlAssessmentModel.organization_id == organization_id]
        if period_id:
            filters.append(ControlAssessmentModel.period_id == period_id)
        if status:
            filters.append(ControlAssessmentModel.status == status)
        if framework_key:
            filters.append(ControlAssessmentModel.framework_key == framework_key)
        if search:
            like = f"%{search.strip()}%"
            filters.append(
                ControlAssessmentModel.id.ilike(like)
                | ControlAssessmentModel.requirement_id.ilike(like)
                | ControlAssessmentModel.framework_key.ilike(like)
                | ControlAssessmentModel.notes.ilike(like)
            )

        sort_col = {
            "updated_at": ControlAssessmentModel.updated_at,
            "created_at": ControlAssessmentModel.created_at,
            "status": ControlAssessmentModel.status,
            "framework_key": ControlAssessmentModel.framework_key,
        }.get(sort, ControlAssessmentModel.updated_at)
        order = sort_col.asc() if sort_dir == "asc" else sort_col.desc()

        total = await self._session.scalar(
            select(func.count()).select_from(ControlAssessmentModel).where(*filters)
        )
        rows = (
            await self._session.scalars(
                select(ControlAssessmentModel)
                .where(*filters)
                .order_by(order)
                .limit(limit)
                .offset(offset)
            )
        ).all()
        items = [
            {
                "id": row.id,
                "organization_id": row.organization_id,
                "profile_id": row.profile_id,
                "period_id": row.period_id,
                "requirement_id": row.requirement_id,
                "framework_key": row.framework_key,
                "status": row.status,
                "evidence_links": row.evidence_links or [],
                "notes": row.notes,
                "created_by": row.created_by,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
            }
            for row in rows
        ]
        return items, int(total or 0)

    async def list_recommendations_page(
        self,
        organization_id: str,
        *,
        status: str | None = None,
        confidence: str | None = None,
        framework_key: str | None = None,
        assessment_id: str | None = None,
        period_id: str | None = None,
        search: str | None = None,
        sort: str = "updated_at",
        sort_dir: SortDir = "desc",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[EvidenceRecommendationModel], int]:
        filters = [EvidenceRecommendationModel.organization_id == organization_id]
        if status:
            filters.append(EvidenceRecommendationModel.status == status)
        if confidence:
            filters.append(EvidenceRecommendationModel.confidence == confidence)
        if framework_key:
            filters.append(EvidenceRecommendationModel.framework_key == framework_key)
        if assessment_id:
            filters.append(EvidenceRecommendationModel.assessment_id == assessment_id)
        if period_id:
            filters.append(EvidenceRecommendationModel.period_id == period_id)
        if search:
            like = f"%{search.strip()}%"
            filters.append(
                EvidenceRecommendationModel.id.ilike(like)
                | EvidenceRecommendationModel.rationale.ilike(like)
                | EvidenceRecommendationModel.source_entity_id.ilike(like)
                | EvidenceRecommendationModel.source_kind.ilike(like)
            )

        sort_col = {
            "updated_at": EvidenceRecommendationModel.updated_at,
            "created_at": EvidenceRecommendationModel.created_at,
            "score": EvidenceRecommendationModel.score,
            "confidence": EvidenceRecommendationModel.confidence,
            "status": EvidenceRecommendationModel.status,
        }.get(sort, EvidenceRecommendationModel.updated_at)
        order = sort_col.asc() if sort_dir == "asc" else sort_col.desc()

        total = await self._session.scalar(
            select(func.count())
            .select_from(EvidenceRecommendationModel)
            .where(*filters)
        )
        rows = (
            await self._session.scalars(
                select(EvidenceRecommendationModel)
                .where(*filters)
                .order_by(order)
                .limit(limit)
                .offset(offset)
            )
        ).all()
        return list(rows), int(total or 0)

    async def list_evidence_page(
        self,
        organization_id: str,
        *,
        category: str | None = None,
        search: str | None = None,
        sort: str = "updated_at",
        sort_dir: SortDir = "desc",
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        # Confirmed evidence from assessment JSONB + recommendation references.
        # Built as two queries then merge in SQL via UNION ALL for pagination.
        confirmed_sql = text(
            """
            SELECT
              'confirmed-' || ca.id || '-' || (link->>'evidence_id') AS id,
              'confirmed'::text AS category,
              'confirmed_control_evidence'::text AS source_kind,
              (link->>'evidence_id') AS entity_id,
              ca.id AS assessment_id,
              NULL::text AS recommendation_id,
              'confirmed'::text AS status,
              NULL::text AS confidence,
              (link->>'confirmed_at')::timestamptz AS updated_at,
              COALESCE(link->>'rationale', '') AS rationale
            FROM control_assessments ca
            CROSS JOIN LATERAL jsonb_array_elements(ca.evidence_links) AS link
            WHERE ca.organization_id = :org_id
            """
        )
        rec_sql = text(
            """
            SELECT
              'rec-' || er.id AS id,
              CASE
                WHEN er.source_kind = 'investigation_evidence' THEN 'investigation_evidence'
                WHEN er.source_kind = 'threat_intelligence' THEN 'threat_intelligence'
                WHEN er.source_kind = 'cloud_scan' THEN 'cloud_scan'
                WHEN er.status = 'linked' THEN 'confirmed'
                ELSE 'recommended'
              END AS category,
              er.source_kind AS source_kind,
              er.source_entity_id AS entity_id,
              er.assessment_id AS assessment_id,
              er.id AS recommendation_id,
              er.status AS status,
              er.confidence AS confidence,
              er.updated_at AS updated_at,
              er.rationale AS rationale
            FROM evidence_recommendations er
            WHERE er.organization_id = :org_id
            """
        )
        union_sql = f"({confirmed_sql.text}) UNION ALL ({rec_sql.text})"
        where_extra = ""
        params: dict[str, Any] = {"org_id": organization_id, "lim": limit, "off": offset}
        if category:
            where_extra += " AND category = :category"
            params["category"] = category
        if search:
            where_extra += (
                " AND (entity_id ILIKE :q OR source_kind ILIKE :q"
                " OR rationale ILIKE :q OR status ILIKE :q)"
            )
            params["q"] = f"%{search.strip()}%"

        sort_col = {
            "updated_at": "updated_at",
            "entity_id": "entity_id",
            "source_kind": "source_kind",
            "status": "status",
        }.get(sort, "updated_at")
        direction = "ASC" if sort_dir == "asc" else "DESC"

        count_result = await self._session.execute(
            text(f"SELECT COUNT(*) FROM ({union_sql}) AS ev WHERE TRUE {where_extra}"),
            params,
        )
        total = int(count_result.scalar_one() or 0)

        page_result = await self._session.execute(
            text(
                f"SELECT * FROM ({union_sql}) AS ev WHERE TRUE {where_extra} "
                f"ORDER BY {sort_col} {direction} NULLS LAST "
                f"LIMIT :lim OFFSET :off"
            ),
            params,
        )
        items = [
            {
                "id": row.id,
                "category": row.category,
                "source_kind": row.source_kind,
                "entity_id": row.entity_id,
                "assessment_id": row.assessment_id,
                "recommendation_id": row.recommendation_id,
                "status": row.status,
                "confidence": row.confidence,
                "updated_at": row.updated_at,
                "rationale": row.rationale or "",
            }
            for row in page_result.all()
        ]
        return items, total

    async def list_timeline_page(
        self,
        organization_id: str,
        *,
        kind: str | None = None,
        search: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        where_extra = ""
        params: dict[str, Any] = {
            "org_id": organization_id,
            "lim": limit,
            "off": offset,
        }
        if kind:
            where_extra += " AND kind = :kind"
            params["kind"] = kind
        if search:
            where_extra += " AND (title ILIKE :q OR detail ILIKE :q)"
            params["q"] = f"%{search.strip()}%"

        wrapped = f"""
            WITH tl AS (
              SELECT
                'assessment-created-' || ca.id AS id,
                ca.created_at AS at,
                'assessment'::text AS kind,
                'Assessment created'::text AS title,
                ca.framework_key || ' · requirement ' || ca.requirement_id AS detail,
                '/compliance/assessments/' || ca.id AS href
              FROM control_assessments ca
              WHERE ca.organization_id = :org_id
              UNION ALL
              SELECT
                'assessment-updated-' || ca.id || '-' || ca.updated_at::text,
                ca.updated_at,
                'status',
                'Status · ' || replace(ca.status, '_', ' '),
                'Control assessment ' || ca.id,
                '/compliance/assessments/' || ca.id
              FROM control_assessments ca
              WHERE ca.organization_id = :org_id
                AND ca.updated_at IS DISTINCT FROM ca.created_at
              UNION ALL
              SELECT
                'evidence-' || ca.id || '-' || (link->>'evidence_id')
                  || '-' || COALESCE(link->>'confirmed_at', ''),
                (link->>'confirmed_at')::timestamptz,
                'evidence',
                'Evidence confirmed',
                (link->>'evidence_id') || ' · ' || COALESCE(link->>'confirmed_by', ''),
                '/compliance/assessments/' || ca.id
              FROM control_assessments ca
              CROSS JOIN LATERAL jsonb_array_elements(ca.evidence_links) AS link
              WHERE ca.organization_id = :org_id
              UNION ALL
              SELECT
                'rec-' || er.id || '-' || er.status || '-' || er.updated_at::text,
                er.updated_at,
                'recommendation',
                'Recommendation ' || replace(er.status, '_', ' '),
                er.confidence || ' · ' || er.source_kind || ':' || er.source_entity_id,
                '/compliance/recommendations?id=' || er.id
              FROM evidence_recommendations er
              WHERE er.organization_id = :org_id
            )
            SELECT {{select}} FROM tl WHERE TRUE {where_extra}
        """
        count_result = await self._session.execute(
            text(wrapped.format(select="COUNT(*)")),
            params,
        )
        total = int(count_result.scalar_one() or 0)
        page_result = await self._session.execute(
            text(
                wrapped.format(select="*")
                + " ORDER BY at DESC NULLS LAST LIMIT :lim OFFSET :off"
            ),
            params,
        )
        items = [
            {
                "id": row.id,
                "at": row.at,
                "kind": row.kind,
                "title": row.title,
                "detail": row.detail,
                "href": row.href,
            }
            for row in page_result.all()
        ]
        return items, total

    async def analytics(self, organization_id: str) -> dict[str, Any]:
        overview = await self.overview_summary(organization_id)
        status_dist = [
            {"label": k.replace("_", " "), "value": v}
            for k, v in overview["status_counts"].items()
        ]
        acceptance = [
            {"label": "accepted", "value": overview["recommendation_counts"]["accepted"]},
            {"label": "linked", "value": overview["recommendation_counts"]["linked"]},
            {"label": "rejected", "value": overview["recommendation_counts"]["rejected"]},
            {
                "label": "recommended",
                "value": overview["recommendation_counts"]["recommended"],
            },
        ]
        decided = (
            overview["recommendation_counts"]["accepted"]
            + overview["recommendation_counts"]["linked"]
            + overview["recommendation_counts"]["rejected"]
        )
        acceptance_pct = (
            0
            if decided == 0
            else round(
                (
                    (
                        overview["recommendation_counts"]["accepted"]
                        + overview["recommendation_counts"]["linked"]
                    )
                    / decided
                )
                * 100
            )
        )

        evidence_growth = (
            await self._session.execute(
                text(
                    """
                    SELECT to_char((link->>'confirmed_at')::timestamptz, 'YYYY-MM') AS month,
                           COUNT(*)::int AS value
                    FROM control_assessments ca
                    CROSS JOIN LATERAL jsonb_array_elements(ca.evidence_links) AS link
                    WHERE ca.organization_id = :org_id
                      AND link->>'confirmed_at' IS NOT NULL
                    GROUP BY 1
                    ORDER BY 1
                    """
                ),
                {"org_id": organization_id},
            )
        ).all()

        validation_velocity = (
            await self._session.execute(
                text(
                    """
                    SELECT to_char(updated_at, 'YYYY-MM') AS month,
                           COUNT(*)::int AS value
                    FROM control_assessments
                    WHERE organization_id = :org_id
                      AND status = 'technically_validated'
                    GROUP BY 1
                    ORDER BY 1
                    """
                ),
                {"org_id": organization_id},
            )
        ).all()

        compliance_trend = (
            await self._session.execute(
                text(
                    """
                    SELECT to_char(updated_at, 'YYYY-MM') AS month,
                           COUNT(*)::int AS total,
                           SUM(CASE WHEN status = 'technically_validated'
                                    THEN 1 ELSE 0 END)::int AS validated
                    FROM control_assessments
                    WHERE organization_id = :org_id
                    GROUP BY 1
                    ORDER BY 1
                    """
                ),
                {"org_id": organization_id},
            )
        ).all()

        return {
            "posture_score": overview["posture_score"],
            "posture_band": overview["posture_band"],
            "validated_count": overview["validated_count"],
            "assessments_total": overview["assessments_total"],
            "evidence_link_count": overview["evidence_link_count"],
            "acceptance_pct": acceptance_pct,
            "status_distribution": status_dist,
            "framework_coverage": [
                {
                    "label": item["framework_key"],
                    "value": item["coverage_pct"],
                }
                for item in overview["framework_progress"]
            ],
            "recommendation_acceptance_mix": acceptance,
            "evidence_growth": [
                {"label": str(r.month), "value": int(r.value)} for r in evidence_growth
            ],
            "validation_velocity": [
                {"label": str(r.month), "value": int(r.value)}
                for r in validation_velocity
            ],
            "compliance_trend": [
                {
                    "label": str(r.month),
                    "value": (
                        0
                        if not r.total
                        else round((int(r.validated) / int(r.total)) * 100)
                    ),
                }
                for r in compliance_trend
            ],
            "recommendation_counts": overview["recommendation_counts"],
        }
