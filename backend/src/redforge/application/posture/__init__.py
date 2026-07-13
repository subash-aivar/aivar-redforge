"""Application layer for the Security Posture bounded context.

Orchestrates snapshot creation, baseline management, trend analysis,
regression detection, and security posture computation.

Application layer — may import domain.posture.*, shared.*, and protocol
ports defined in this package. Must NOT import infrastructure.
"""
