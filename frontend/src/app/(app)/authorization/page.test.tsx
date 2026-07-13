import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { api } from "@/lib/api";
import AuthorizationPage from "./page";
import type {
  Authorization,
  AuthorizationSummary,
  DecisionHistoryEntry,
} from "@/lib/authorizations";

vi.mock("@/lib/api", () => ({
  api: { get: vi.fn(), post: vi.fn() },
}));

const SUMMARY: AuthorizationSummary = {
  draft: 2,
  pending_approval: 1,
  active: 3,
  rejected: 0,
  revoked: 0,
  expired: 0,
};

function makeAuthorization(overrides: Partial<Authorization> = {}): Authorization {
  return {
    id: "auth-1",
    organization_id: "org-1",
    requester_user_id: "user-requester",
    status: "draft",
    action_classes: ["safe_validation"],
    scope: [{ entity_type: "ai_target", entity_id: "target-1" }],
    valid_from: new Date(0).toISOString(),
    valid_until: new Date(1000 * 60 * 60).toISOString(),
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
    approval: null,
    ...overrides,
  };
}

function makeDecision(overrides: Partial<DecisionHistoryEntry> = {}): DecisionHistoryEntry {
  return {
    id: "decision-1",
    authorization_id: "auth-1",
    actor_user_id: "user-requester",
    action_class: "safe_validation",
    raw_action_class: "safe_validation",
    entity_refs: [{ entity_type: "ai_target", entity_id: "target-1" }],
    decision: "allow",
    reason_code: "ALLOWED_BY_ACTIVE_AUTHORIZATION",
    evaluated_at: new Date(0).toISOString(),
    ...overrides,
  };
}

function mockApi(opts: {
  summary?: AuthorizationSummary;
  authorizations?: Authorization[];
  decisions?: DecisionHistoryEntry[];
  currentUserId?: string;
}) {
  const {
    summary = SUMMARY,
    authorizations = [makeAuthorization()],
    decisions = [],
    currentUserId = "user-current",
  } = opts;
  vi.mocked(api.get).mockImplementation((path: string) => {
    if (path.includes("/authorizations/summary")) return Promise.resolve(summary);
    if (path.includes("/authorizations/decisions")) return Promise.resolve(decisions);
    if (path.includes("/authorizations")) return Promise.resolve(authorizations);
    if (path.includes("/auth/me")) {
      return Promise.resolve({
        user_id: currentUserId,
        email: "me@test.com",
        display_name: "Me",
        status: "active",
      });
    }
    return Promise.reject(new Error(`unexpected path: ${path}`));
  });
}

describe("AuthorizationPage overview", () => {
  it("renders backend-derived counts, not fabricated totals", async () => {
    mockApi({});
    render(<AuthorizationPage />);
    await waitFor(() => {
      expect(screen.getByText("2")).toBeInTheDocument(); // draft
    });
    expect(screen.getByText("3")).toBeInTheDocument(); // active
  });

  it("renders an explicit empty state, not a blank list", async () => {
    mockApi({ authorizations: [] });
    render(<AuthorizationPage />);
    await waitFor(() => {
      expect(screen.getByText(/No authorizations match/i)).toBeInTheDocument();
    });
  });

  it("surfaces an API failure truthfully instead of a silent empty state", async () => {
    vi.mocked(api.get).mockRejectedValue(new Error("network down"));
    render(<AuthorizationPage />);
    await waitFor(() => {
      expect(screen.getByText(/UNAVAILABLE/i)).toBeInTheDocument();
    });
  });
});

describe("AuthorizationPage status rendering", () => {
  it("renders an unrecognized status as UNKNOWN, not a crash", async () => {
    mockApi({ authorizations: [makeAuthorization({ status: "some_future_status" })] });
    render(<AuthorizationPage />);
    await waitFor(() => {
      expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
    });
  });

  it("renders DRAFT authorizations with their action classes", async () => {
    mockApi({ authorizations: [makeAuthorization()] });
    render(<AuthorizationPage />);
    await waitFor(() => {
      expect(screen.getByText("DRAFT")).toBeInTheDocument();
    });
    expect(screen.getByText("SAFE_VALIDATION")).toBeInTheDocument();
  });
});

describe("AuthorizationPage detail view and lifecycle-gated actions", () => {
  it("shows Submit for a DRAFT authorization", async () => {
    mockApi({ authorizations: [makeAuthorization({ status: "draft" })] });
    render(<AuthorizationPage />);
    await waitFor(() => screen.getByText("DRAFT"));
    fireEvent.click(screen.getByText("DRAFT"));
    await waitFor(() => {
      expect(screen.getByText("Submit for Approval")).toBeInTheDocument();
    });
    expect(screen.queryByText("Approve")).not.toBeInTheDocument();
    expect(screen.queryByText("Revoke")).not.toBeInTheDocument();
  });

  it("shows Approve/Reject for a PENDING_APPROVAL authorization by a different user", async () => {
    mockApi({
      authorizations: [
        makeAuthorization({ status: "pending_approval", requester_user_id: "someone-else" }),
      ],
      currentUserId: "user-current",
    });
    render(<AuthorizationPage />);
    await waitFor(() => screen.getByText("PENDING_APPROVAL"));
    fireEvent.click(screen.getByText("PENDING_APPROVAL"));
    await waitFor(() => {
      expect(screen.getByText("Approve")).toBeInTheDocument();
    });
    expect(screen.getByText("Reject")).toBeInTheDocument();
    expect(screen.getByText("Approve")).not.toBeDisabled();
  });

  it("disables Approve/Reject when the current user is the requester (self-approval)", async () => {
    mockApi({
      authorizations: [
        makeAuthorization({ status: "pending_approval", requester_user_id: "user-current" }),
      ],
      currentUserId: "user-current",
    });
    render(<AuthorizationPage />);
    await waitFor(() => screen.getByText("PENDING_APPROVAL"));
    fireEvent.click(screen.getByText("PENDING_APPROVAL"));
    await waitFor(() => {
      expect(screen.getByText(/cannot approve your own request/i)).toBeInTheDocument();
    });
    expect(screen.getByText("Approve")).toBeDisabled();
  });

  it("shows Revoke for an ACTIVE authorization and its approval history", async () => {
    mockApi({
      authorizations: [
        makeAuthorization({
          status: "active",
          approval: {
            id: "appr-1",
            authorization_id: "auth-1",
            requester_user_id: "user-requester",
            approver_user_id: "user-approver",
            decision: "approved",
            requested_at: new Date(0).toISOString(),
            decided_at: new Date(1000).toISOString(),
            reason: "",
          },
        }),
      ],
    });
    render(<AuthorizationPage />);
    await waitFor(() => screen.getByText("ACTIVE"));
    fireEvent.click(screen.getByText("ACTIVE"));
    await waitFor(() => {
      expect(screen.getByText("Revoke")).toBeInTheDocument();
    });
    expect(screen.getByText(/APPROVED/)).toBeInTheDocument();
    expect(screen.getByText(/user-approver/)).toBeInTheDocument();
  });

  it("shows no lifecycle action for a terminal REJECTED authorization", async () => {
    mockApi({ authorizations: [makeAuthorization({ status: "rejected" })] });
    render(<AuthorizationPage />);
    await waitFor(() => screen.getByText("REJECTED"));
    fireEvent.click(screen.getByText("REJECTED"));
    await waitFor(() => {
      expect(screen.getByText("Close")).toBeInTheDocument();
    });
    expect(screen.queryByText("Submit for Approval")).not.toBeInTheDocument();
    expect(screen.queryByText("Approve")).not.toBeInTheDocument();
    expect(screen.queryByText("Revoke")).not.toBeInTheDocument();
  });
});

describe("AuthorizationPage decision history tab", () => {
  it("renders decision history entries with their reason codes", async () => {
    mockApi({ decisions: [makeDecision()] });
    render(<AuthorizationPage />);
    await waitFor(() => screen.getByText("Policy Decision History"));
    fireEvent.click(screen.getByText("Policy Decision History"));
    await waitFor(() => {
      expect(screen.getByText("ALLOWED_BY_ACTIVE_AUTHORIZATION")).toBeInTheDocument();
    });
    expect(screen.getByText("ALLOW")).toBeInTheDocument();
  });

  it("renders an explicit empty state for decision history", async () => {
    mockApi({ decisions: [] });
    render(<AuthorizationPage />);
    await waitFor(() => screen.getByText("Policy Decision History"));
    fireEvent.click(screen.getByText("Policy Decision History"));
    await waitFor(() => {
      expect(screen.getByText(/No policy decisions recorded yet/i)).toBeInTheDocument();
    });
  });
});

describe("AuthorizationPage create form", () => {
  it("requires at least one action class before submitting", async () => {
    mockApi({});
    render(<AuthorizationPage />);
    await waitFor(() => screen.getByText("New Authorization"));
    fireEvent.click(screen.getByText("New Authorization"));
    const submitButtons = await screen.findAllByText("Create Draft");
    fireEvent.click(submitButtons[submitButtons.length - 1]);
    await waitFor(() => {
      expect(screen.getByText(/Select at least one action class/i)).toBeInTheDocument();
    });
    expect(api.post).not.toHaveBeenCalled();
  });
});
