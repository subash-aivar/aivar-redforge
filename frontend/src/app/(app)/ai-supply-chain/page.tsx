"use client";

import { Suspense } from "react";
import { PageHeader } from "@/components/cc";
import AISupplyChainInner from "./AISupplyChainInner";

export default function AISupplyChainPage() {
  return (
    <Suspense fallback={<PageHeader title="AI Supply Chain — Provenance Lookup" />}>
      <AISupplyChainInner />
    </Suspense>
  );
}
