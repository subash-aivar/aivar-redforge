import { describe, expect, it, vi, afterEach } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { GlobalStatusBar } from "@/components/platform/GlobalStatusBar";
import { EventBusProvider } from "@/components/platform/EventBusProvider";
import * as runtime from "@/lib/runtime";
import * as streamHook from "@/lib/useSecurityOperationsStream";

vi.mock("@/lib/runtime");
vi.mock("@/lib/useSecurityOperationsStream");

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function renderBar(organizationName?: string) {
  vi.mocked(streamHook.useSecurityOperationsStream).mockReturnValue({
    connectionState: "connected",
    events: [],
    lastEventReceivedAt: null,
  });
  return render(
    <EventBusProvider>
      <GlobalStatusBar organizationName={organizationName} />
    </EventBusProvider>
  );
}

describe("GlobalStatusBar", () => {
  it("renders real platform health from /api/v1/runtime/status, never a fabricated value", async () => {
    vi.mocked(runtime.getRuntimeStatus).mockResolvedValue({
      phase: "running",
      overall_health: "healthy",
      component_count: 5,
      unhealthy_components: [],
      circuit_states: {},
      dlq_total_entries: 0,
      metrics_sample_count: 10,
      checked_at: new Date().toISOString(),
      product_edition: "full",
    });

    renderBar("Acme Security");

    await waitFor(() => expect(screen.getByText("healthy")).toBeInTheDocument());
    expect(screen.getByText("(5/5 components)")).toBeInTheDocument();
    expect(screen.getByText("Acme Security")).toBeInTheDocument();
    expect(screen.queryByText(/DLQ entries/)).not.toBeInTheDocument();
  });

  it("shows an honest unavailable state instead of fabricating health when the endpoint fails", async () => {
    vi.mocked(runtime.getRuntimeStatus).mockRejectedValue(new Error("network error"));

    renderBar();

    await waitFor(() => expect(screen.getByText("Platform health unavailable")).toBeInTheDocument());
  });

  it("surfaces real DLQ depth when the backend reports entries", async () => {
    vi.mocked(runtime.getRuntimeStatus).mockResolvedValue({
      phase: "running",
      overall_health: "degraded",
      component_count: 5,
      unhealthy_components: ["dlq-worker"],
      circuit_states: {},
      dlq_total_entries: 3,
      metrics_sample_count: 10,
      checked_at: new Date().toISOString(),
      product_edition: "full",
    });

    renderBar();

    await waitFor(() => expect(screen.getByText("3 DLQ entries")).toBeInTheDocument());
  });
});
