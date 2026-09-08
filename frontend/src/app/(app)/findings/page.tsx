"use client";

import { Suspense } from "react";
import { PageHeader } from "@/components/cc";
import FindingsInner from "./FindingsInner";

export default function FindingsPage() {
  return (
    <Suspense fallback={<PageHeader title="Security Findings" />}>
      <FindingsInner />
    </Suspense>
  );
}
