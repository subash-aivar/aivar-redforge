import { describe, it, expect, vi, beforeEach } from "vitest";
import { api } from "@/lib/api";
import { getForIncident, createReview, addLesson, finalizeReview } from "@/lib/lessonsLearned";

vi.mock("@/lib/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/api")>();
  return { ...actual, api: { ...actual.api, get: vi.fn(), post: vi.fn() } };
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe("lessonsLearned client — verified against real backend routes", () => {
  // Regression test for a real bug found in browser QA: this client
  // previously called `GET /api/v1/lessons-learned` (list) and
  // `GET /api/v1/lessons-learned/{reviewId}` (get by id) — neither
  // route exists (confirmed via live curl: 405 and would-be-404
  // respectively). The only real read path is
  // `GET /api/v1/lessons-learned/incident/{incident_id}`
  // (`lessons_learned/api/v1/routes.py`), and the real response shape
  // has `lessons`/`actions` as integer counts, not nested object
  // arrays — confirmed against `LessonsApplicationService.get`.
  it("calls the real per-incident lookup path", async () => {
    vi.mocked(api.get).mockResolvedValue({
      ll_id: "ll-1",
      status: "open",
      incident_id: "inc-1",
      lessons: 2,
      actions: 1,
      quality_score: 4.5,
      techniques: ["T1078"],
    });
    const result = await getForIncident("inc-1");
    expect(api.get).toHaveBeenCalledWith("/api/v1/lessons-learned/incident/inc-1");
    expect(result.lessons).toBe(2);
    expect(typeof result.lessons).toBe("number");
  });

  it("creates a review with the real body shape", async () => {
    vi.mocked(api.post).mockResolvedValue({ ll_id: "ll-1", status: "open" });
    await createReview("inc-1", ["T1078"]);
    expect(api.post).toHaveBeenCalledWith("/api/v1/lessons-learned", {
      incident_id: "inc-1",
      technique_ids: ["T1078"],
    });
  });

  it("adds a lesson keyed by ll_id, not review_id", async () => {
    vi.mocked(api.post).mockResolvedValue({});
    await addLesson("ll-1", { category: "process", description: "d", impact_summary: "i" });
    expect(api.post).toHaveBeenCalledWith("/api/v1/lessons-learned/ll-1/lessons", {
      category: "process",
      description: "d",
      impact_summary: "i",
    });
  });

  it("finalizes with the real actor body", async () => {
    vi.mocked(api.post).mockResolvedValue({});
    await finalizeReview("ll-1");
    expect(api.post).toHaveBeenCalledWith("/api/v1/lessons-learned/ll-1/finalize", { actor: "ui" });
  });
});
