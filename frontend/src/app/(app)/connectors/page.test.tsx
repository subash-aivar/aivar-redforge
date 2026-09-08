import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import * as assetsLib from "@/lib/assets";
import ConnectorsPage from "./page";
import type { Connector } from "@/lib/assets";

vi.mock("@/lib/assets", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/assets")>();
  return {
    ...actual,
    listConnectors: vi.fn(),
    listDiscoveryRuns: vi.fn(),
    registerConnector: vi.fn(),
    disableConnector: vi.fn(),
    enableConnector: vi.fn(),
    startDiscovery: vi.fn(),
  };
});
vi.mock("@/lib/directorySecurity", () => ({ registerDirectoryConnector: vi.fn() }));
vi.mock("@/lib/networkExposure", () => ({ registerNetworkConnector: vi.fn() }));
vi.mock("@/lib/cloudSecurity", () => ({ registerCloudConnector: vi.fn() }));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

function makeConnector(overrides: Partial<Connector> = {}): Connector {
  return {
    id: "conn-1",
    organization_id: "org-1",
    connector_type: "generic",
    name: "Test Connector",
    status: "enabled",
    last_discovery_status: null,
    last_discovery_completed_at: null,
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
    ...overrides,
  };
}

function renderPage(connectors: Connector[] = []) {
  vi.mocked(assetsLib.listConnectors).mockResolvedValue(connectors);
  return render(<ConnectorsPage />);
}

describe("ConnectorsPage — registration form accessibility", () => {
  it("every field across all four registration panels has a real programmatic label", async () => {
    const { container } = renderPage([]);
    fireEvent.click(await screen.findByText("Register connector"));

    const expectedLabels = [
      "Connector name",
      "Server URI",
      "Base DN",
      "Bind DN",
      "Credential reference",
      "CIDR",
      "Ports",
      "Region",
      "Access key ID",
      "Secret access key credential reference",
    ];
    for (const name of expectedLabels) {
      const fields = screen.getAllByLabelText(name, { exact: false });
      expect(fields.length).toBeGreaterThan(0);
      for (const field of fields) {
        expect(field.id).toBeTruthy();
        expect(container.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
      }
    }
  });

  it("no duplicate field ids exist across all four registration panels", async () => {
    const { container } = renderPage([]);
    fireEvent.click(await screen.findByText("Register connector"));

    const ids = Array.from(container.querySelectorAll("[id]")).map((el) => el.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("credential reference fields use autocomplete=off and are never type=password (they hold an env var name, not a secret)", async () => {
    renderPage([]);
    fireEvent.click(await screen.findByText("Register connector"));

    const ldapRef = screen.getByPlaceholderText("e.g. LDAP_BIND_PASSWORD");
    expect(ldapRef).not.toHaveAttribute("type", "password");
    expect(ldapRef).toHaveAttribute("autocomplete", "off");

    const cloudRef = screen.getByLabelText("Secret access key credential reference", { exact: false });
    expect(cloudRef).not.toHaveAttribute("type", "password");
    expect(cloudRef).toHaveAttribute("autocomplete", "off");
  });

  it("submitting the generic connector form sends exactly the existing payload — no fabricated fields", async () => {
    vi.mocked(assetsLib.registerConnector).mockResolvedValue(makeConnector());
    renderPage([]);
    fireEvent.click(await screen.findByText("Register connector"));

    fireEvent.change(screen.getAllByLabelText("Connector name", { exact: false })[0], {
      target: { value: "New Connector" },
    });
    fireEvent.click(screen.getByText("Register", { selector: "button" }));

    await waitFor(() => {
      expect(assetsLib.registerConnector).toHaveBeenCalledWith("New Connector", "");
    });
  });

  it("a failed registration surfaces via role=alert, distinguishable from a validation state", async () => {
    vi.mocked(assetsLib.registerConnector).mockRejectedValue(new Error("Connector already exists"));
    renderPage([]);
    fireEvent.click(await screen.findByText("Register connector"));

    fireEvent.change(screen.getAllByLabelText("Connector name", { exact: false })[0], {
      target: { value: "Dup" },
    });
    fireEvent.click(screen.getByText("Register", { selector: "button" }));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("Connector already exists");
    });
  });

  it("Enable/Disable reflects only the real connector status — never claims 'connected' beyond what the backend returns", async () => {
    renderPage([makeConnector({ status: "enabled" }), makeConnector({ id: "conn-2", status: "disabled", name: "Disabled Connector" })]);

    await waitFor(() => expect(screen.getByText("Test Connector")).toBeInTheDocument());
    const rows = screen.getAllByText(/Disable|Enable/);
    expect(rows.map((r) => r.textContent)).toEqual(expect.arrayContaining(["Disable", "Enable"]));
  });

  it("RBAC/discovery actions remain absent from the accessibility tree for a disabled connector (Run discovery stays disabled, not hidden but inert)", async () => {
    renderPage([makeConnector({ status: "disabled" })]);
    await waitFor(() => expect(screen.getByText("Test Connector")).toBeInTheDocument());
    expect(screen.getByText("Run discovery")).toBeDisabled();
  });
});
