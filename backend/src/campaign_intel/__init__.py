"""campaign_intel — RedForge-native adversary-campaign intelligence.

This context is the sole owner of RedForge-native *threat-intelligence*
campaign identity (`(scope, canonical_name)`): a record of a real-world
adversary campaign — its aliases, observation timeline, objectives,
motivation, targeted regions and sectors, real-world operational status,
evidence-first record lifecycle, source attribution and append-only
version history.

It is emphatically NOT `src/campaign` / `src/campaignexecution`, which
model RedForge's OWN red-team operational campaigns (scheduling,
approvals, execution). Those are unrelated bounded contexts and are
never imported, referenced or extended from here.

Relationships from a `Campaign` to any other intelligence entity (IOC,
malware, threat actor, attack pattern, infrastructure) are NOT modelled
here — they are expressed exclusively by the already-certified
`intelligence_relationships` bounded context, whose `CAMPAIGN` entity
type accepts this context's `CampaignId` as an opaque `entity_id`
(`MALWARE_TO_CAMPAIGN`, `CAMPAIGN_TO_THREAT_ACTOR`,
`INFRASTRUCTURE_TO_CAMPAIGN`, `IOC_TO_CAMPAIGN`).
"""

from __future__ import annotations
