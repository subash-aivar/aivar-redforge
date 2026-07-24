import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { api } from "@/lib/api";
import IntegrationsPage from "./page";
import type { ConnectorPlugin, ConnectorRegistration, DiscoveredAsset } from "@/lib/integrations";

vi.mock("@/lib/api", () => ({
  api: { get: vi.fn(), post: vi.fn(), delete: vi.fn() },
}));

function makePlugin(overrides: Partial<ConnectorPlugin> = {}): ConnectorPlugin {
  return {
    connector_id: "openai",
    display_name: "OpenAI",
    category: "AI_VENDOR",
    auth_model: "API_KEY",
    credential_fields: [],
    config_fields: [],
    docs: {
      purpose: "",
      supported_features: [],
      required_credentials: "",
      required_permissions: "",
      required_vendor_configuration: "",
      validation_process: "",
      connectivity_test: "",
      health_check: "",
      synchronization_strategy: "",
      troubleshooting_guide: "",
      common_failure_scenarios: "",
      recovery_steps: "",
      required_scopes: [],
      callback_urls: [],
      firewall_notes: "",
    },
    capabilities: ["health_check", "discovery"],
    ...overrides,
  };
}

function makeConnector(overrides: Partial<ConnectorRegistration> = {}): ConnectorRegistration {
  return {
    connector_id: "conn-1",
    tenant_id: "tenant-1",
    connector_type: "openai",
    display_name: "OpenAI Prod",
    status: "HEALTHY",
    circuit_state: "CLOSED",
    credential_vault_key: "vault-key-123",
    credential_type: "API_KEY",
    ...overrides,
  };
}

function makeAsset(overrides: Partial<DiscoveredAsset> = {}): DiscoveredAsset {
  return {
    asset_id: "asset-1",
    tenant_id: "tenant-1",
    connector_id: "conn-1",
    external_id: "gpt-4",
    name: "gpt-4",
    category: "AI_MODEL",
    vendor: "OPENAI",
    region: null,
    owner: null,
    security_state: "UNKNOWN",
    compliance_state: "UNKNOWN",
    health_status: null,
    risk_score: 0,
    tags: {},
    metadata: {},
    relationships: [],
    discovered_at: new Date(0).toISOString(),
    last_synced_at: new Date(0).toISOString(),
    ...overrides,
  };
}

function mockApi({
  catalog,
  connectors,
  assets,
}: {
  catalog: ConnectorPlugin[];
  connectors: ConnectorRegistration[];
  assets: DiscoveredAsset[];
}) {
  vi.mocked(api.get).mockImplementation((path: string) => {
    if (path.includes("/integration-hub/catalog")) return Promise.resolve(catalog);
    if (path.includes("/integration-hub/connectors")) return Promise.resolve(connectors);
    if (path.includes("/integration-hub/assets")) return Promise.resolve(assets);
    return Promise.resolve([]);
  });
}

describe("IntegrationsPage asset honesty", () => {
  it("renders 'Not Yet Evaluated' instead of a fabricated 0 risk score / UNKNOWN pill", async () => {
    mockApi({
      catalog: [makePlugin()],
      connectors: [makeConnector()],
      assets: [makeAsset()],
    });
    render(<IntegrationsPage />);

    fireEvent.click(await screen.findByText("Asset Inventory"));

    const notYetEvaluated = await screen.findAllByText("Not Yet Evaluated");
    // Once for the risk column, once for the security-state column (if
    // rendered) — at minimum one instance must appear, and no raw "0" or
    // "UNKNOWN" text should leak through for the never-scored asset.
    expect(notYetEvaluated.length).toBeGreaterThan(0);
    expect(screen.queryByText("UNKNOWN")).not.toBeInTheDocument();
  });

  it("disables Run Discovery for a connector whose plugin lacks the discovery capability", async () => {
    mockApi({
      catalog: [makePlugin({ connector_id: "no-discovery", capabilities: ["health_check"] })],
      connectors: [makeConnector({ connector_type: "no-discovery", display_name: "Static Vendor" })],
      assets: [],
    });
    render(<IntegrationsPage />);

    fireEvent.click(await screen.findByText("Asset Inventory"));

    const button = await screen.findByRole("button", { name: /Run Discovery — Static Vendor/i });
    expect(button).toBeDisabled();
  });

  it("enables Run Discovery for a connector whose plugin has the discovery capability", async () => {
    mockApi({
      catalog: [makePlugin()],
      connectors: [makeConnector()],
      assets: [],
    });
    render(<IntegrationsPage />);

    fireEvent.click(await screen.findByText("Asset Inventory"));

    const button = await screen.findByRole("button", { name: /Run Discovery — OpenAI Prod/i });
    expect(button).not.toBeDisabled();
  });
});
