"""intelligence_relationships — RedForge-native cross-entity threat
intelligence relationships (M51.4 Phase C1).

Owns the typed, evidence-first, epistemically-graded *edges* between
threat intelligence entities (IOC, malware, tool, threat actor,
campaign, attack pattern, infrastructure, threat report). It never
owns the entities themselves: every endpoint of a relationship is an
opaque `EntityRef` (entity_type + opaque entity_id string). Existence
of the three RedForge-native endpoint kinds (IOC, threat actor,
attack pattern) is validated read-only through narrow ACL ports
(`IIocIdentityPort`, `IThreatActorIdentityPort`,
`IAttackPatternIdentityPort`) — this context never imports
`ioc_intelligence`, `threat_actor_intel`, or `attack_pattern_intel`
domain classes. Malware/campaign/tool/infrastructure/threat-report
endpoints have no owning module at all and remain opaque strings by
design.

`tenant_id` is `TenantId | None`: `None` means a global
RedForge-curated relationship (requires `platform:*` permission to
mutate); a real `TenantId` means a tenant-scoped relationship.
"""

from __future__ import annotations
