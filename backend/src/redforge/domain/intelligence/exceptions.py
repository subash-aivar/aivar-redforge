"""Exceptions for the AI Security Intelligence bounded context."""

from __future__ import annotations


class IntelligenceDomainError(Exception):
    """Base for all intelligence domain exceptions."""


class RecommendationNotFoundError(IntelligenceDomainError):
    def __init__(self, recommendation_id: str) -> None:
        super().__init__(f"Recommendation {recommendation_id!r} not found.")
        self.recommendation_id = recommendation_id


class InsightNotFoundError(IntelligenceDomainError):
    def __init__(self, insight_id: str) -> None:
        super().__init__(f"SecurityInsight {insight_id!r} not found.")
        self.insight_id = insight_id


class RecommendationAlreadyTerminalError(IntelligenceDomainError):
    def __init__(self, recommendation_id: str, status: str) -> None:
        super().__init__(
            f"Recommendation {recommendation_id!r} is in terminal state {status!r}."
        )
        self.recommendation_id = recommendation_id
        self.status = status


class DuplicateRecommendationError(IntelligenceDomainError):
    """Raised when a rule would produce a duplicate recommendation for the same key."""

    def __init__(self, key: str) -> None:
        super().__init__(f"Duplicate recommendation for key {key!r}.")
        self.key = key


class IntelligenceContextError(IntelligenceDomainError):
    """Raised when the IntelligenceContext is missing required data."""
