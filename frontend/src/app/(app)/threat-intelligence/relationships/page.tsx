"use client";

import { ComingSoon } from "@/components/threat-intelligence/ComingSoon";
import { THREAT_INTEL_CAPABILITIES } from "@/lib/threatIntelShell";

const capability = THREAT_INTEL_CAPABILITIES.find((c) => c.key === "relationships")!;

export default function RelationshipsPage() {
  return <ComingSoon capability={capability} />;
}
