"use client";

import { ComingSoon } from "@/components/threat-intelligence/ComingSoon";
import { THREAT_INTEL_CAPABILITIES } from "@/lib/threatIntelShell";

const capability = THREAT_INTEL_CAPABILITIES.find((c) => c.key === "threat-actors")!;

export default function ThreatActorsPage() {
  return <ComingSoon capability={capability} />;
}
