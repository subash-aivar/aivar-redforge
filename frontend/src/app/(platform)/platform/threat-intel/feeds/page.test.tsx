import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup, fireEvent } from "@testing-library/react";

vi.mock("next/link", () => ({
  default: ({ href, children, ...rest }: { href: string; children: React.ReactNode }) =>
    <a href={href} {...rest}>{children}</a>,
}));

vi.mock("@/lib/feedSync", () => ({
  listFeeds: vi.fn(),
  activateFeed: vi.fn(),
  pauseFeed: vi.fn(),
  disableFeed: vi.fn(),
  triggerFeedSync: vi.fn(),
  feedStatusColor: () => "border-emerald-800 bg-emerald-950/50 text-emerald-300",
  formatInterval: (s: number) => `${s}s`,
  SOURCE_KIND_LABELS: { mitre_attack: "MITRE ATT&CK", nvd_cve: "NVD CVE" },
}));

import * as feedSync from "@/lib/feedSync";
import FeedManagementPage from "./page";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const feed = {
  id: "feed-1",
  feed_key: "mitre_attack_v15",
  display_name: "MITRE ATT&CK v15",
  source_kind: "mitre_attack",
  scope: "global",
  organization_id: null,
  status: "active",
  connector_config: {},
  credential_ref: null,
  schedule_interval_seconds: 3600,
  retry_policy: { max_attempts: 3, base_delay_seconds: 60, max_delay_seconds: 3600, jitter_factor: 0.1 },
  checkpoint: null,
  consecutive_failure_count: 0,
  last_sync_started_at: null,
  last_sync_completed_at: null,
  last_sync_status: null,
  next_sync_due_at: null,
  created_at: "2024-01-01T00:00:00Z",
  updated_at: "2024-01-01T00:00:00Z",
  created_by: "user-1",
  updated_by: "user-1",
};

describe("FeedManagementPage", () => {
  it("shows loading then renders feed", async () => {
    vi.mocked(feedSync.listFeeds).mockResolvedValue({ items: [feed], total: 1 });
    render(<FeedManagementPage />);
    expect(screen.getByText("Loading…")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("MITRE ATT&CK v15")).toBeInTheDocument());
    expect(screen.getByText("1 total")).toBeInTheDocument();
  });

  it("shows error when API fails", async () => {
    vi.mocked(feedSync.listFeeds).mockRejectedValue(new Error("Network error"));
    render(<FeedManagementPage />);
    await waitFor(() =>
      expect(screen.getByText("Failed to load feeds.")).toBeInTheDocument(),
    );
  });

  it("shows empty state with register link when no feeds", async () => {
    vi.mocked(feedSync.listFeeds).mockResolvedValue({ items: [], total: 0 });
    render(<FeedManagementPage />);
    await waitFor(() =>
      expect(screen.getByText("No feeds found.")).toBeInTheDocument(),
    );
    expect(screen.getByText("Register a feed.")).toBeInTheDocument();
  });

  it("trigger sync calls API and reloads", async () => {
    vi.mocked(feedSync.listFeeds).mockResolvedValue({ items: [feed], total: 1 });
    vi.mocked(feedSync.triggerFeedSync).mockResolvedValue({
      id: "run-1",
      feed_id: feed.id,
      status: "running",
      trigger: "manual",
      checkpoint_before: null,
      checkpoint_after: null,
      items_fetched: 0,
      items_processed: 0,
      items_failed: 0,
      retry_attempts_used: 0,
      error_message: null,
      started_at: "2024-01-01T00:00:00Z",
      finished_at: null,
      created_by: "user-1",
    });
    render(<FeedManagementPage />);
    await waitFor(() => screen.getByText("Sync Now"));
    fireEvent.click(screen.getByText("Sync Now"));
    await waitFor(() => expect(feedSync.triggerFeedSync).toHaveBeenCalledWith(feed.id));
  });

  it("shows action error when sync fails", async () => {
    vi.mocked(feedSync.listFeeds).mockResolvedValue({ items: [feed], total: 1 });
    vi.mocked(feedSync.triggerFeedSync).mockRejectedValue(new Error("fail"));
    render(<FeedManagementPage />);
    await waitFor(() => screen.getByText("Sync Now"));
    fireEvent.click(screen.getByText("Sync Now"));
    await waitFor(() =>
      expect(screen.getByText(/Action 'sync' failed/)).toBeInTheDocument(),
    );
  });
});
