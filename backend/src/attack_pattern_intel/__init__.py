"""attack_pattern_intel — RedForge-native ATT&CK pattern intelligence
(M51.3 Phase B1).

ACL-over-legacy-identity: `redforge.domain.threat_intel` (M22) remains
the sole canonical owner of MITRE technique/tactic identity. This
bounded context never duplicates that catalog — it references
technique identity by opaque `technique_id` (validated through the
`IMitreTechniqueIdentityPort` ACL) and owns everything legacy does
not: evidence-first lifecycle, detection guidance, mitigation
references, procedure examples, native relationship metadata, and
version history.
"""

from __future__ import annotations
