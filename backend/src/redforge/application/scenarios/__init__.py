"""Scenario Engine — enterprise AI security validation composition.

Maps enterprise AI system types to platform capabilities.
Customers think in systems (Banking Assistant, HR Copilot, MCP Server).
Scenarios translate that into: which attacks, which evaluation, what pass criteria.

Architecture: Pure composition layer. References existing:
- Attack categories (from Attack Library)
- Evaluation profiles (from Evaluation Engine)
- Execution strategies (from Runtime)
- Target capabilities (from Providers/Targets)

Does NOT own: execution, evaluation, findings, risk, providers.
"""
