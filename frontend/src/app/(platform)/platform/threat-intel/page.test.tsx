import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, cleanup, fireEvent } from "@testing-library/react";

vi.mock("@/lib/referenceData", () => ({
  listTactics: vi.fn(),
  listTechniquesByTactic: vi.fn(),
  searchTechniques: vi.fn(),
  listKevVulnerabilities: vi.fn(),
  listHighEpssVulnerabilities: vi.fn(),
  listIngestions: vi.fn(),
  cvssColor: () => "border-red-800 bg-red-950/60 text-red-300",
  cvssLabel: () => "Critical",
}));

import * as rd from "@/lib/referenceData";
import ThreatIntelReferencePage from "./page";

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

const tactic = {
  tactic_id: "TA0001",
  name: "Reconnaissance",
  shortname: "recon",
  description: "Gathering info.",
  stix_id: "x-stix-1",
  url: null,
  created_at: "2024-01-01T00:00:00Z",
  updated_at: "2024-01-01T00:00:00Z",
};

const vuln = {
  cve_id: "CVE-2024-0001",
  description: "A critical RCE.",
  cvss_v3: { version: "3.1", base_score: 9.8, vector: "AV:N", severity: "CRITICAL" },
  cvss_v2_score: null,
  epss: { probability: 0.7, percentile: 0.99, model_date: "2024-01-01" },
  is_kev: true,
  kev_date_added: "2024-01-01",
  kev_due_date: null,
  kev_vulnerability_name: "Test Vuln",
  kev_short_description: "Short",
  kev_required_action: "Patch immediately",
  kev_known_ransomware_use: false,
  published_at: null,
  last_modified_at: null,
  source_last_synced_at: null,
  created_at: "2024-01-01T00:00:00Z",
  updated_at: "2024-01-01T00:00:00Z",
};

describe("ThreatIntelReferencePage", () => {
  it("shows loading state then renders tactics", async () => {
    vi.mocked(rd.listTactics).mockResolvedValue([tactic]);
    render(<ThreatIntelReferencePage />);
    expect(screen.getByText("Loading…")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Reconnaissance")).toBeInTheDocument());
    expect(screen.getByText("TA0001")).toBeInTheDocument();
  });

  it("shows error banner when tactics API fails", async () => {
    vi.mocked(rd.listTactics).mockRejectedValue(new Error("Network error"));
    render(<ThreatIntelReferencePage />);
    await waitFor(() =>
      expect(screen.getByText("Failed to load tactics.")).toBeInTheDocument(),
    );
  });

  it("shows empty state when no tactics ingested", async () => {
    vi.mocked(rd.listTactics).mockResolvedValue([]);
    render(<ThreatIntelReferencePage />);
    await waitFor(() =>
      expect(
        screen.getByText("No tactics ingested yet. Run an ATT&CK feed."),
      ).toBeInTheDocument(),
    );
  });

  it("switches to Vulnerabilities tab and loads KEV data", async () => {
    vi.mocked(rd.listTactics).mockResolvedValue([]);
    vi.mocked(rd.listKevVulnerabilities).mockResolvedValue([vuln]);
    render(<ThreatIntelReferencePage />);

    fireEvent.click(screen.getByText("Vulnerabilities"));
    await waitFor(() => expect(screen.getByText("CVE-2024-0001")).toBeInTheDocument());
    // EPSS probability is 0.7 → 70.0%
    expect(screen.getByText("70.0%")).toBeInTheDocument();
  });

  it("shows vulnerability error when API fails", async () => {
    vi.mocked(rd.listTactics).mockResolvedValue([]);
    vi.mocked(rd.listKevVulnerabilities).mockRejectedValue(new Error("fail"));
    render(<ThreatIntelReferencePage />);
    fireEvent.click(screen.getByText("Vulnerabilities"));
    await waitFor(() =>
      expect(screen.getByText("Failed to load vulnerabilities.")).toBeInTheDocument(),
    );
  });

  it("shows empty state for vulnerabilities when API returns empty list", async () => {
    vi.mocked(rd.listTactics).mockResolvedValue([]);
    vi.mocked(rd.listKevVulnerabilities).mockResolvedValue([]);
    render(<ThreatIntelReferencePage />);
    fireEvent.click(screen.getByText("Vulnerabilities"));
    await waitFor(() =>
      expect(
        screen.getByText("No vulnerabilities found for this filter."),
      ).toBeInTheDocument(),
    );
  });

  it("shows ingestion log records", async () => {
    vi.mocked(rd.listTactics).mockResolvedValue([]);
    const record = {
      id: "rec-1",
      source_system: "mitre_attack",
      scope: "global",
      organization_id: null,
      object_type: "attack-pattern",
      external_id: "attack-pattern--abc",
      content_hash: "hash1",
      ingested_at: "2024-01-01T00:00:00Z",
      batch_id: null,
    };
    vi.mocked(rd.listIngestions).mockResolvedValue([record]);
    render(<ThreatIntelReferencePage />);
    fireEvent.click(screen.getByText("Ingestion Log"));
    await waitFor(() => expect(screen.getByText("mitre_attack")).toBeInTheDocument());
    expect(screen.getByText("attack-pattern")).toBeInTheDocument();
  });
});
