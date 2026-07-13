"""Evaluation quality signal keys and value object for campaign intelligence.

Defines the canonical string keys used to transport evaluation quality signals
through CampaignIntelligenceContext.metadata (dict[str, str]).

Why dict[str, str]?
  CampaignIntelligenceContext is in the domain layer. EvaluationFeedback is in
  the application layer. The domain cannot import application types. The correct
  pattern is stringly-typed transport with strict parsing at the consumer
  boundary (application layer).

This module lives in the domain layer and defines only:
  - Key constants (no application layer imports)
  - EvalSignals — a domain value object representing parsed eval quality signals
  - parse_eval_signals() — a strict fail-closed parser

The application layer (campaign_intelligence.py) imports EvalSignals and uses
it instead of raw string key lookups. This eliminates magic string keys
scattered across modules.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from enum import StrEnum, unique

# ─── Key constants ────────────────────────────────────────────────────────────
# These are the canonical metadata keys. Do not use string literals in caller
# code — import these constants instead.

EVAL_KEY_RECOMMENDED_ACTION = "eval_recommended_action"
EVAL_KEY_EVALUATION_QUALITY = "eval_evaluation_quality"
EVAL_KEY_REQUIRES_MORE_EVIDENCE = "eval_requires_more_evidence"
EVAL_KEY_CONSENSUS_STATE = "eval_consensus_state"


# ─── Signal value types ───────────────────────────────────────────────────────


@unique
class EvalQuality(StrEnum):
    """Parsed evaluation quality level from eval_evaluation_quality key."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# ─── Typed value object ───────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class EvalSignals:
    """Parsed evaluation quality signals from CampaignIntelligenceContext.metadata.

    Immutable value object. Unknown or malformed values are represented as None
    (fail-closed: unknown signals are ignored, not acted upon).

    The string-typed transport is the boundary contract between the domain and
    application layers. EvalSignals is the domain-side representation after
    strict parsing.
    """

    recommended_action: str | None   # CampaignDecisionAction.value or None
    evaluation_quality: EvalQuality | None
    requires_more_evidence: bool
    consensus_state: str | None      # EvaluatorConsensus.value or None


# ─── Parser ───────────────────────────────────────────────────────────────────


def parse_eval_signals(metadata: dict[str, str]) -> EvalSignals:
    """Parse eval quality signals from metadata dict (strict, fail-closed).

    Any unrecognized or malformed value is treated as absent (None / False).
    Raises nothing — this function is unconditionally safe to call.
    """
    if not metadata:
        return EvalSignals(
            recommended_action=None,
            evaluation_quality=None,
            requires_more_evidence=False,
            consensus_state=None,
        )

    # recommended_action: accept as-is (validated by caller against CampaignDecisionAction)
    recommended_action: str | None = metadata.get(EVAL_KEY_RECOMMENDED_ACTION) or None

    # evaluation_quality: must be a known EvalQuality value
    evaluation_quality: EvalQuality | None = None
    raw_quality = metadata.get(EVAL_KEY_EVALUATION_QUALITY, "")
    if raw_quality:
        with contextlib.suppress(ValueError):
            evaluation_quality = EvalQuality(raw_quality)

    # requires_more_evidence: "true" → True; anything else → False (fail-safe)
    requires_more_evidence = metadata.get(EVAL_KEY_REQUIRES_MORE_EVIDENCE, "") == "true"

    # consensus_state: accept as-is (validated by caller against EvaluatorConsensus)
    consensus_state: str | None = metadata.get(EVAL_KEY_CONSENSUS_STATE) or None

    return EvalSignals(
        recommended_action=recommended_action,
        evaluation_quality=evaluation_quality,
        requires_more_evidence=requires_more_evidence,
        consensus_state=consensus_state,
    )
