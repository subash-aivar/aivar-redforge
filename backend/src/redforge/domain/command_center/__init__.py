"""Security Operations Command Center domain — M18.

M18 is overwhelmingly a READ MODEL over M1-M17 truth. This domain
package holds only the small amount of genuinely-new domain logic the
command center owns:

  - value_objects: closed, server-owned enums (integration types &
    status, network zone types, behavior-signal kinds/severities).
  - posture: the deterministic, versioned, fully-explainable posture
    score formula (a weighted deduction over real active-condition and
    correlation counts — never a probabilistic or ML risk score).

Everything else the command center surfaces (activity feed, drift,
network exposure, runtime health, incidents, inventory) is read from
its owning bounded context's existing tables — the command center adds
no second source of authoritative truth for any of them.
"""
