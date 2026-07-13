"""Evidence Correlation Engine.

Transforms isolated Evidence records into correlated attack chains.
Applies rules to cluster related evidence and identify multi-step
attack patterns. Extensible for future ML/embedding-based correlation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum, unique
from typing import Protocol, runtime_checkable

# ─── Types ────────────────────────────────────────────────────────────────────


@unique
class CorrelationType(StrEnum):
    """Types of correlation between evidence records."""

    SAME_RUN = "same_run"
    SAME_TARGET = "same_target"
    SAME_ATTACK_TYPE = "same_attack_type"
    SAME_PROVIDER = "same_provider"
    TEMPORAL_PROXIMITY = "temporal_proximity"
    REPEATED_FAILURE = "repeated_failure"
    ESCALATION_PATTERN = "escalation_pattern"


@dataclass(frozen=True, slots=True)
class CorrelationScore:
    """Confidence score for a correlation."""

    value: float  # 0.0 - 1.0

    def __post_init__(self) -> None:
        if self.value < 0.0 or self.value > 1.0:
            raise ValueError(f"Score must be 0.0-1.0, got {self.value}")

    @property
    def is_strong(self) -> bool:
        return self.value >= 0.7

    def combine(self, other: CorrelationScore) -> CorrelationScore:
        """Combine two scores (max, not sum — avoids exceeding 1.0)."""
        return CorrelationScore(max(self.value, other.value))


@dataclass(frozen=True, slots=True)
class CorrelationReason:
    """Why two evidence records are correlated."""

    correlation_type: CorrelationType
    score: CorrelationScore
    description: str


# ─── Evidence Input (lightweight view — no domain dependency) ─────────────────


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """Lightweight evidence view for correlation processing.

    This is NOT the domain entity — it's an input DTO that decouples
    correlation from the Evidence aggregate.
    """

    evidence_id: str
    run_id: str
    target_id: str
    attack_id: str
    attack_type: str
    result: str  # pass/fail/error
    confidence: float
    executed_at: datetime
    duration_ms: int = 0


# ─── Correlation Results ──────────────────────────────────────────────────────


@dataclass
class EvidenceCluster:
    """A group of correlated evidence records."""

    cluster_id: str
    evidence_ids: list[str]
    correlation_score: CorrelationScore
    reasons: list[CorrelationReason]
    attack_types: set[str] = field(default_factory=set)

    @property
    def size(self) -> int:
        return len(self.evidence_ids)


@dataclass(frozen=True, slots=True)
class AttackChain:
    """A sequence of correlated attacks forming a chain."""

    chain_id: str
    evidence_ids: list[str]
    attack_ids: list[str]
    run_id: str
    target_id: str
    correlation_score: CorrelationScore
    summary: str
    root_cause_candidate: str
    timeline_start: datetime
    timeline_end: datetime

    @property
    def length(self) -> int:
        return len(self.evidence_ids)

    @property
    def duration(self) -> timedelta:
        return self.timeline_end - self.timeline_start


@dataclass(frozen=True)
class CorrelationResult:
    """Complete output of the correlation engine."""

    clusters: list[EvidenceCluster]
    attack_chains: list[AttackChain]
    total_evidence: int
    correlated_evidence: int
    uncorrelated_evidence: int

    @property
    def correlation_rate(self) -> float:
        if self.total_evidence == 0:
            return 0.0
        return self.correlated_evidence / self.total_evidence


# ─── Correlation Rules ────────────────────────────────────────────────────────


@runtime_checkable
class CorrelationRule(Protocol):
    """Interface for correlation rules.

    Rules evaluate pairs of evidence and return a score.
    Extensible: add ML rules, embedding rules, graph rules.
    """

    @property
    def rule_name(self) -> str: ...

    def correlate(
        self, a: EvidenceRecord, b: EvidenceRecord
    ) -> CorrelationReason | None:
        """Return correlation reason if records are related, None otherwise."""
        ...


class SameRunRule:
    """Correlates evidence from the same validation run."""

    @property
    def rule_name(self) -> str:
        return "same_run"

    def correlate(
        self, a: EvidenceRecord, b: EvidenceRecord
    ) -> CorrelationReason | None:
        if a.run_id == b.run_id:
            return CorrelationReason(
                correlation_type=CorrelationType.SAME_RUN,
                score=CorrelationScore(0.9),
                description="Same validation run",
            )
        return None


class SameTargetRule:
    """Correlates evidence targeting the same AI system."""

    @property
    def rule_name(self) -> str:
        return "same_target"

    def correlate(
        self, a: EvidenceRecord, b: EvidenceRecord
    ) -> CorrelationReason | None:
        if a.target_id == b.target_id and a.run_id != b.run_id:
            return CorrelationReason(
                correlation_type=CorrelationType.SAME_TARGET,
                score=CorrelationScore(0.5),
                description="Same target, different runs",
            )
        return None


class SameAttackTypeRule:
    """Correlates evidence using the same attack technique."""

    @property
    def rule_name(self) -> str:
        return "same_attack_type"

    def correlate(
        self, a: EvidenceRecord, b: EvidenceRecord
    ) -> CorrelationReason | None:
        if a.attack_type == b.attack_type and a.evidence_id != b.evidence_id:
            return CorrelationReason(
                correlation_type=CorrelationType.SAME_ATTACK_TYPE,
                score=CorrelationScore(0.6),
                description=f"Same attack type: {a.attack_type}",
            )
        return None


class TemporalProximityRule:
    """Correlates evidence executed within a time window."""

    def __init__(self, window: timedelta = timedelta(minutes=5)) -> None:
        self._window = window

    @property
    def rule_name(self) -> str:
        return "temporal_proximity"

    def correlate(
        self, a: EvidenceRecord, b: EvidenceRecord
    ) -> CorrelationReason | None:
        if a.evidence_id == b.evidence_id:
            return None
        delta = abs((a.executed_at - b.executed_at).total_seconds())
        if delta <= self._window.total_seconds():
            score = max(0.3, 1.0 - (delta / self._window.total_seconds()))
            return CorrelationReason(
                correlation_type=CorrelationType.TEMPORAL_PROXIMITY,
                score=CorrelationScore(min(score, 0.8)),
                description=f"Executed within {int(delta)}s",
            )
        return None


class RepeatedFailureRule:
    """Correlates repeated failures against the same target."""

    @property
    def rule_name(self) -> str:
        return "repeated_failure"

    def correlate(
        self, a: EvidenceRecord, b: EvidenceRecord
    ) -> CorrelationReason | None:
        if (
            a.result == "fail"
            and b.result == "fail"
            and a.target_id == b.target_id
            and a.evidence_id != b.evidence_id
        ):
            return CorrelationReason(
                correlation_type=CorrelationType.REPEATED_FAILURE,
                score=CorrelationScore(0.8),
                description="Repeated failures on same target",
            )
        return None


# ─── Correlation Engine ───────────────────────────────────────────────────────


class EvidenceCorrelationEngine:
    """Applies correlation rules to evidence and produces attack chains.

    Stateless, composable, extensible. Add new rules (including ML-based)
    by implementing the CorrelationRule protocol.
    """

    def __init__(self, rules: list[CorrelationRule] | None = None) -> None:
        self._rules: list[CorrelationRule] = rules or [
            SameRunRule(),
            SameAttackTypeRule(),
            TemporalProximityRule(),
            RepeatedFailureRule(),
        ]

    def correlate(self, evidence: list[EvidenceRecord]) -> CorrelationResult:
        """Process evidence records and produce correlation results."""
        if not evidence:
            return CorrelationResult(
                clusters=[], attack_chains=[],
                total_evidence=0, correlated_evidence=0, uncorrelated_evidence=0,
            )

        # Build pairwise correlations
        clusters = self._build_clusters(evidence)
        chains = self._build_chains(evidence, clusters)

        correlated_ids = set()
        for c in clusters:
            correlated_ids.update(c.evidence_ids)

        return CorrelationResult(
            clusters=clusters,
            attack_chains=chains,
            total_evidence=len(evidence),
            correlated_evidence=len(correlated_ids),
            uncorrelated_evidence=len(evidence) - len(correlated_ids),
        )

    def _build_clusters(self, evidence: list[EvidenceRecord]) -> list[EvidenceCluster]:
        """Group correlated evidence using union-find approach."""
        # Adjacency: evidence_id → set of correlated evidence_ids + reasons
        correlations: dict[str, list[tuple[str, CorrelationReason]]] = {
            e.evidence_id: [] for e in evidence
        }

        for i, a in enumerate(evidence):
            for b in evidence[i + 1 :]:
                for rule in self._rules:
                    reason = rule.correlate(a, b)
                    if reason is not None:
                        correlations[a.evidence_id].append((b.evidence_id, reason))
                        correlations[b.evidence_id].append((a.evidence_id, reason))

        # Build clusters via connected components
        visited: set[str] = set()
        clusters: list[EvidenceCluster] = []
        cluster_idx = 0

        for eid in correlations:
            if eid in visited or not correlations[eid]:
                continue
            # BFS to find connected component
            component: list[str] = []
            reasons: list[CorrelationReason] = []
            queue = [eid]
            while queue:
                current = queue.pop(0)
                if current in visited:
                    continue
                visited.add(current)
                component.append(current)
                for neighbor, reason in correlations[current]:
                    reasons.append(reason)
                    if neighbor not in visited:
                        queue.append(neighbor)

            if len(component) > 1:
                max_score = max(r.score.value for r in reasons) if reasons else 0.0
                attack_types = {
                    e.attack_type for e in evidence if e.evidence_id in component
                }
                clusters.append(EvidenceCluster(
                    cluster_id=f"cluster-{cluster_idx}",
                    evidence_ids=component,
                    correlation_score=CorrelationScore(max_score),
                    reasons=list({r.description: r for r in reasons}.values()),
                    attack_types=attack_types,
                ))
                cluster_idx += 1

        return clusters

    def _build_chains(
        self, evidence: list[EvidenceRecord], clusters: list[EvidenceCluster]
    ) -> list[AttackChain]:
        """Convert clusters with temporal ordering into attack chains."""
        evidence_map = {e.evidence_id: e for e in evidence}
        chains: list[AttackChain] = []

        for cluster in clusters:
            if cluster.size < 2:
                continue

            # Sort cluster evidence by execution time
            cluster_evidence = sorted(
                [evidence_map[eid] for eid in cluster.evidence_ids],
                key=lambda e: e.executed_at,
            )

            chains.append(AttackChain(
                chain_id=f"chain-{len(chains)}",
                evidence_ids=[e.evidence_id for e in cluster_evidence],
                attack_ids=list({e.attack_id for e in cluster_evidence}),
                run_id=cluster_evidence[0].run_id,
                target_id=cluster_evidence[0].target_id,
                correlation_score=cluster.correlation_score,
                summary=self._chain_summary(cluster_evidence),
                root_cause_candidate=cluster_evidence[0].attack_type,
                timeline_start=cluster_evidence[0].executed_at,
                timeline_end=cluster_evidence[-1].executed_at,
            ))

        return chains

    @staticmethod
    def _chain_summary(evidence: list[EvidenceRecord]) -> str:
        """Generate a human-readable chain summary."""
        types = list(dict.fromkeys(e.attack_type for e in evidence))
        failures = sum(1 for e in evidence if e.result == "fail")
        return (
            f"{len(evidence)} steps across {len(types)} attack types, "
            f"{failures} failures detected"
        )
