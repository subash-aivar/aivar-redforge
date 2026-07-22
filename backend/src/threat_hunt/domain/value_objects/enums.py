from __future__ import annotations

from enum import StrEnum


class ThreatHuntCandidateStatus(StrEnum):
    CANDIDATE = "candidate"
    UNDER_REVIEW = "under_review"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    PROMOTED = "promoted"


class DetectionRuleFormat(StrEnum):
    SIGMA = "sigma"
    KQL = "kql"
    SPL = "spl"
