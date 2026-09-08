import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup, within } from "@testing-library/react";
import * as mlPipeline from "@/lib/mlPipeline";
import MLPipelinePage from "./page";

vi.mock("@/lib/mlPipeline", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/mlPipeline")>();
  return {
    ...actual,
    scheduleTraining: vi.fn(),
    listModels: vi.fn(),
  };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function mockAll() {
  vi.mocked(mlPipeline.listModels).mockResolvedValue([]);
}

async function openTrainModal() {
  const trigger = screen.getByText("Train Model");
  trigger.focus();
  fireEvent.click(trigger);
  await waitFor(() => {
    expect(screen.getByRole("dialog", { name: "Schedule Model Training" })).toBeInTheDocument();
  });
  return trigger;
}

describe("MLPipelinePage — Train Model modal", () => {
  it("opens a labelled dialog with real programmatic labels on Model Type and Dataset ID", async () => {
    mockAll();
    render(<MLPipelinePage />);
    await waitFor(() => screen.getByText("Train Model"));
    await openTrainModal();

    const modelType = screen.getByLabelText("Model Type", { exact: false });
    expect(modelType.id).toBeTruthy();
    expect(document.querySelector(`label[for="${modelType.id}"]`)).not.toBeNull();

    const datasetId = screen.getByLabelText("Dataset ID", { exact: false });
    expect(datasetId.id).toBeTruthy();
    expect(document.querySelector(`label[for="${datasetId.id}"]`)).not.toBeNull();
  });

  it("Cancel closes the modal and sends no request", async () => {
    mockAll();
    render(<MLPipelinePage />);
    await waitFor(() => screen.getByText("Train Model"));
    await openTrainModal();

    fireEvent.click(screen.getByText("Cancel"));

    expect(screen.queryByRole("dialog", { name: "Schedule Model Training" })).not.toBeInTheDocument();
    expect(mlPipeline.scheduleTraining).not.toHaveBeenCalled();
  });

  it("Escape closes the modal and returns focus to the trigger", async () => {
    mockAll();
    render(<MLPipelinePage />);
    await waitFor(() => screen.getByText("Train Model"));
    const trigger = await openTrainModal();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog", { name: "Schedule Model Training" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("surfaces a failed schedule as a role=alert error instead of failing silently", async () => {
    mockAll();
    vi.mocked(mlPipeline.scheduleTraining).mockRejectedValue(new Error("training queue full"));
    render(<MLPipelinePage />);
    await waitFor(() => screen.getByText("Train Model"));
    await openTrainModal();

    fireEvent.click(within(screen.getByRole("dialog")).getByText("Train"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("training queue full");
    });
    expect(screen.getByRole("dialog", { name: "Schedule Model Training" })).toBeInTheDocument();
  });

  it("submits the exact expected payload and reloads models on success", async () => {
    mockAll();
    vi.mocked(mlPipeline.scheduleTraining).mockResolvedValue({} as never);
    render(<MLPipelinePage />);
    await waitFor(() => screen.getByText("Train Model"));
    await openTrainModal();

    fireEvent.change(screen.getByLabelText("Dataset ID", { exact: false }), {
      target: { value: "dataset-42" },
    });
    fireEvent.click(within(screen.getByRole("dialog")).getByText("Train"));

    await waitFor(() => {
      expect(mlPipeline.scheduleTraining).toHaveBeenCalledWith({
        model_type: "ANOMALY_DETECTOR",
        dataset_id: "dataset-42",
      });
    });
    await waitFor(() => {
      expect(screen.queryByRole("dialog", { name: "Schedule Model Training" })).not.toBeInTheDocument();
    });
  });
});
