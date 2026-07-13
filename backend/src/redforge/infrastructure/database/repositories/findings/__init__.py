"""Findings repository — infrastructure implementation."""

from redforge.infrastructure.database.repositories.findings.repository import (
    SqlAlchemyFindingRepository,
)

__all__ = ["SqlAlchemyFindingRepository"]
