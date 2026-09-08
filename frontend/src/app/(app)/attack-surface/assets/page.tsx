"use client";

import { Suspense } from "react";
import { PageHeader } from "@/components/cc";
import AttackSurfaceAssetsInner from "./AttackSurfaceAssetsInner";

export default function AttackSurfaceAssetsPage() {
  return (
    <Suspense fallback={<PageHeader title="Attack Surface Assets" />}>
      <AttackSurfaceAssetsInner />
    </Suspense>
  );
}
