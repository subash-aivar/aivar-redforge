"""Shared red-team projection module for platform ProjectionRegistry."""

from execution.application.projections.red_team_graph_projection import (
    RedTeamGraphProjection,
    RedTeamKGNode,
)

__all__ = ["RedTeamGraphProjection", "RedTeamKGNode"]
