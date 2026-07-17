"use client";

import { Suspense } from "react";
import { LoadingRow, PageHeader } from "@/components/cc";
import RecommendationQueueInner from "./RecommendationQueueInner";

export default function RecommendationQueuePage() {
  return (
    <Suspense
      fallback={
        <>
          <PageHeader title="Recommendation Review Queue" />
          <LoadingRow />
        </>
      }
    >
      <RecommendationQueueInner />
    </Suspense>
  );
}
