import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup, within } from "@testing-library/react";
import * as postureForecasting from "@/lib/postureForecasting";
import PostureForecastingPage from "./page";

vi.mock("@/lib/postureForecasting", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/postureForecasting")>();
  return {
    ...actual,
    generateForecast: vi.fn(),
    getLatestForecast: vi.fn(),
  };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function mockAll() {
  vi.mocked(postureForecasting.getLatestForecast).mockRejectedValue(new Error("no forecast yet"));
}

async function openGenerateModal() {
  const trigger = screen.getByText("Generate Forecast");
  trigger.focus();
  fireEvent.click(trigger);
  await waitFor(() => {
    expect(screen.getByRole("dialog", { name: "Generate Posture Forecast" })).toBeInTheDocument();
  });
  return trigger;
}

describe("PostureForecastingPage — Generate Forecast modal", () => {
  it("opens a labelled dialog with real programmatic labels on all numeric inputs", async () => {
    mockAll();
    render(<PostureForecastingPage />);
    await waitFor(() => screen.getByText("Generate Forecast"));
    await openGenerateModal();

    for (const label of [
      "Baseline Exposure Score",
      "Remediation Velocity",
      "Open Critical Findings",
      "Open High Findings",
    ]) {
      const field = screen.getByLabelText(label, { exact: false });
      expect(field.id).toBeTruthy();
      expect(document.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
    }
  });

  it("Cancel closes the modal and sends no request", async () => {
    mockAll();
    render(<PostureForecastingPage />);
    await waitFor(() => screen.getByText("Generate Forecast"));
    await openGenerateModal();

    fireEvent.click(screen.getByText("Cancel"));

    expect(screen.queryByRole("dialog", { name: "Generate Posture Forecast" })).not.toBeInTheDocument();
    expect(postureForecasting.generateForecast).not.toHaveBeenCalled();
  });

  it("Escape closes the modal and returns focus to the trigger", async () => {
    mockAll();
    render(<PostureForecastingPage />);
    await waitFor(() => screen.getByText("Generate Forecast"));
    const trigger = await openGenerateModal();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog", { name: "Generate Posture Forecast" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("surfaces a failed generation as a role=alert error instead of failing silently", async () => {
    mockAll();
    vi.mocked(postureForecasting.generateForecast).mockRejectedValue(new Error("invalid baseline"));
    render(<PostureForecastingPage />);
    await waitFor(() => screen.getByText("Generate Forecast"));
    await openGenerateModal();

    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByText("Generate"));

    await waitFor(() => {
      expect(within(dialog).getByRole("alert")).toHaveTextContent("invalid baseline");
    });
    expect(screen.getByRole("dialog", { name: "Generate Posture Forecast" })).toBeInTheDocument();
  });

  it("submits the exact expected payload and closes on success", async () => {
    mockAll();
    vi.mocked(postureForecasting.generateForecast).mockResolvedValue({
      baseline_exposure_score: 5,
      predicted_30d: 4,
      predicted_60d: 3,
      predicted_90d: 2,
      generated_at: new Date(0).toISOString(),
    } as never);
    render(<PostureForecastingPage />);
    await waitFor(() => screen.getByText("Generate Forecast"));
    await openGenerateModal();

    fireEvent.click(within(screen.getByRole("dialog")).getByText("Generate"));

    await waitFor(() => {
      expect(postureForecasting.generateForecast).toHaveBeenCalledWith({
        baseline_exposure_score: 5,
        remediation_velocity_per_day: 1,
        open_critical_count: 0,
        open_high_count: 0,
      });
    });
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Generate Posture Forecast" })).not.toBeInTheDocument();
    });
  });
});
