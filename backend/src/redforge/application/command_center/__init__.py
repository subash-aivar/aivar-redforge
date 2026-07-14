"""Security Operations Command Center application services — M18.

Read-only, tenant-scoped services that COMPOSE existing M1-M17 truth
into the command center's operational surface. Scope discipline
(inherited from M15's security_operations context):

  - No service here owns or mutates another bounded context's
    authoritative domain state. The only writes M18 performs are to its
    own two boundary tables — network zone assignments (explicit admin
    classification) and integration provider descriptors — both audited.
  - Every metric, aggregate, and signal traces to a real persisted row.
    Nothing is fabricated; capabilities with no data source report an
    explicit not-configured/unavailable state.
  - Behavior analytics (UEBA/HBA/NBA) are deterministic rule evaluations
    over real audit / drift rows, each signal carrying links to the
    source records that produced it — never ML or opaque scoring.
"""
