"use client";

import { Suspense } from "react";
import { LoadingRow, PageHeader } from "@/components/cc";
import AssessmentWorkspaceInner from "./AssessmentWorkspaceInner";

export default function AssessmentWorkspacePage() {
  return (
    <Suspense
      fallback={
        <>
          <PageHeader title="Assessment Workspace" />
          <LoadingRow />
        </>
      }
    >
      <AssessmentWorkspaceInner />
    </Suspense>
  );
}
