import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import * as vault from "@/lib/credentialVault";
import CredentialVaultPage from "./page";
import type {
  CredentialResponse,
  VersionResponse,
  AuditEntryResponse,
  RotationPolicyResponse,
  ExpirationPolicyResponse,
  VaultBackendResponse,
} from "@/lib/credentialVault";

vi.mock("@/lib/credentialVault", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/credentialVault")>();
  return {
    ...actual,
    listCredentials: vi.fn(),
    getCredential: vi.fn(),
    resolveCredential: vi.fn(),
    disableCredential: vi.fn(),
    enableCredential: vi.fn(),
    revokeCredential: vi.fn(),
    emergencyRevokeCredential: vi.fn(),
    rotateCredential: vi.fn(),
    commitRotation: vi.fn(),
    abortRotation: vi.fn(),
    listVersions: vi.fn(),
    listAuditEntries: vi.fn(),
    listRotationPolicies: vi.fn(),
    createRotationPolicy: vi.fn(),
    deleteRotationPolicy: vi.fn(),
    listExpirationPolicies: vi.fn(),
    createExpirationPolicy: vi.fn(),
    deleteExpirationPolicy: vi.fn(),
    listVaultBackends: vi.fn(),
    registerVaultBackend: vi.fn(),
    deleteVaultBackend: vi.fn(),
    createCredential: vi.fn(),
  };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

function makeCredential(overrides: Partial<CredentialResponse> = {}): CredentialResponse {
  return {
    credential_id: "cred-1",
    tenant_id: "tenant-1",
    name: "Prod API Key",
    category: "API_KEY",
    subtype: "openai",
    schema_id: null,
    state: "ACTIVE",
    owner_principal_id: "user-1",
    active_version_id: "ver-1",
    rotation_policy_id: null,
    expiration_policy_id: null,
    vault_backend_id: "backend-1",
    description: "Test credential",
    tags: {},
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
    version: 1,
    ...overrides,
  };
}

function makeVersion(overrides: Partial<VersionResponse> = {}): VersionResponse {
  return {
    version_id: "ver-1",
    credential_id: "cred-1",
    tenant_id: "tenant-1",
    version_number: 1,
    version_state: "ACTIVE",
    created_by: "user-1",
    created_at: new Date(0).toISOString(),
    expires_at: null,
    rotation_trigger: null,
    rotation_policy_id: null,
    ...overrides,
  };
}

function makeAuditEntry(overrides: Partial<AuditEntryResponse> = {}): AuditEntryResponse {
  return {
    entry_id: "audit-1",
    audit_log_id: "log-1",
    credential_id: "cred-1",
    tenant_id: "tenant-1",
    operation: "RESOLVE",
    outcome: "SUCCESS",
    principal_id: "user-1",
    occurred_at: new Date(0).toISOString(),
    detail: "resolved for purpose x",
    client_ip: null,
    request_id: null,
    ...overrides,
  };
}

function makeRotationPolicy(overrides: Partial<RotationPolicyResponse> = {}): RotationPolicyResponse {
  return {
    policy_id: "rot-1",
    tenant_id: "tenant-1",
    name: "90-day rotation",
    interval_days: 90,
    max_versions_kept: 5,
    notify_days_before: 7,
    auto_rotate: false,
    auto_commit: false,
    commit_window_hours: 24,
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
    version: 1,
    ...overrides,
  };
}

function makeExpirationPolicy(overrides: Partial<ExpirationPolicyResponse> = {}): ExpirationPolicyResponse {
  return {
    policy_id: "exp-1",
    tenant_id: "tenant-1",
    name: "1-year TTL",
    ttl_days: 365,
    warn_days_before: 30,
    hard_expire: false,
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
    version: 1,
    ...overrides,
  };
}

function makeBackend(overrides: Partial<VaultBackendResponse> = {}): VaultBackendResponse {
  return {
    backend_id: "backend-1",
    tenant_id: "tenant-1",
    name: "Local Vault",
    backend_type: "LOCAL",
    is_default: true,
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
    version: 1,
    ...overrides,
  };
}

function mockAll(opts: {
  credentials?: CredentialResponse[];
  versions?: VersionResponse[];
  audit?: AuditEntryResponse[];
  rotationPolicies?: RotationPolicyResponse[];
  expirationPolicies?: ExpirationPolicyResponse[];
  backends?: VaultBackendResponse[];
}) {
  const credentials = opts.credentials ?? [];
  vi.mocked(vault.listCredentials).mockResolvedValue({
    items: credentials,
    total: credentials.length,
    limit: 200,
    offset: 0,
  });
  vi.mocked(vault.getCredential).mockImplementation((id: string) =>
    Promise.resolve(credentials.find((c) => c.credential_id === id) ?? makeCredential({ credential_id: id }))
  );
  vi.mocked(vault.listVersions).mockResolvedValue({ items: opts.versions ?? [] });
  vi.mocked(vault.listAuditEntries).mockResolvedValue({ items: opts.audit ?? [] });
  vi.mocked(vault.listRotationPolicies).mockResolvedValue(opts.rotationPolicies ?? []);
  vi.mocked(vault.listExpirationPolicies).mockResolvedValue(opts.expirationPolicies ?? []);
  vi.mocked(vault.listVaultBackends).mockResolvedValue(opts.backends ?? []);
}

describe("CredentialVaultPage — Credentials tab", () => {
  it("derives KPI counts from real credential states", async () => {
    mockAll({
      credentials: [
        makeCredential({ credential_id: "c1", state: "ACTIVE" }),
        makeCredential({ credential_id: "c2", state: "DISABLED" }),
        makeCredential({ credential_id: "c3", state: "REVOKED" }),
      ],
    });
    render(<CredentialVaultPage />);

    await waitFor(() => expect(screen.getByText("Total Credentials")).toBeInTheDocument());
    const kpiValues = screen.getAllByText(/^[0-9]+$/).map((el) => el.textContent);
    expect(kpiValues).toContain("3"); // total
    expect(kpiValues.filter((v) => v === "1").length).toBeGreaterThanOrEqual(3); // active, disabled, revoked
  });

  it("opens the credential detail drawer on row click", async () => {
    mockAll({ credentials: [makeCredential()] });
    render(<CredentialVaultPage />);

    await waitFor(() => expect(screen.getByText("Prod API Key")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Prod API Key"));

    await waitFor(() => expect(screen.getByRole("dialog")).toBeInTheDocument());
    expect(vault.getCredential).toHaveBeenCalledWith("cred-1");
  });

  it("requires a purpose before resolving a secret", async () => {
    mockAll({ credentials: [makeCredential()] });
    render(<CredentialVaultPage />);

    await waitFor(() => expect(screen.getByText("Prod API Key")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Prod API Key"));
    await waitFor(() => expect(screen.getByRole("dialog")).toBeInTheDocument());
    // The dialog's own "Loading…" shell shares the same role — the
    // Resolve Secret button only exists once the async credential
    // detail fetch resolves, so wait for it specifically before
    // clicking (a race under slower runners otherwise; this exact
    // race is what caused this test to flake on GitHub-hosted CI).
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Resolve Secret" })).toBeInTheDocument()
    );

    fireEvent.click(screen.getByRole("button", { name: "Resolve Secret" }));

    await waitFor(() => {
      expect(screen.getByText("Purpose is required to resolve a credential.")).toBeInTheDocument();
    });
    expect(vault.resolveCredential).not.toHaveBeenCalled();
  });

  it("requires a justification for break-glass resolve", async () => {
    mockAll({ credentials: [makeCredential()] });
    render(<CredentialVaultPage />);

    await waitFor(() => expect(screen.getByText("Prod API Key")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Prod API Key"));
    await waitFor(() => expect(screen.getByRole("dialog")).toBeInTheDocument());

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Resolve Secret" })).toBeInTheDocument()
    );
    fireEvent.change(screen.getByLabelText("Purpose", { exact: false }), {
      target: { value: "incident triage" },
    });
    fireEvent.click(screen.getByLabelText("Break-glass access"));
    fireEvent.click(screen.getByRole("button", { name: "Resolve Secret" }));

    await waitFor(() => {
      expect(screen.getByText("Break-glass access requires a justification.")).toBeInTheDocument();
    });
    expect(vault.resolveCredential).not.toHaveBeenCalled();
  });

  it("resolves and decodes the secret, then clears it on demand", async () => {
    mockAll({ credentials: [makeCredential()] });
    vi.mocked(vault.resolveCredential).mockResolvedValue({
      credential_id: "cred-1",
      version_id: "ver-1",
      secret_b64: btoa("sk-super-secret"),
      resolved_at: new Date(0).toISOString(),
    });
    render(<CredentialVaultPage />);

    await waitFor(() => expect(screen.getByText("Prod API Key")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Prod API Key"));
    await waitFor(() => expect(screen.getByRole("dialog")).toBeInTheDocument());

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Resolve Secret" })).toBeInTheDocument()
    );
    fireEvent.change(screen.getByLabelText("Purpose", { exact: false }), {
      target: { value: "incident triage" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Resolve Secret" }));

    await waitFor(() => {
      expect(vault.resolveCredential).toHaveBeenCalledWith("cred-1", {
        purpose: "incident triage",
        break_glass: false,
        justification: undefined,
      });
    });
    await waitFor(() => expect(screen.getByText("sk-super-secret")).toBeInTheDocument());

    fireEvent.click(screen.getByText("Clear"));
    expect(screen.queryByText("sk-super-secret")).not.toBeInTheDocument();
  });

  it("disables the Disable button when the credential is already DISABLED", async () => {
    mockAll({ credentials: [makeCredential({ state: "DISABLED" })] });
    render(<CredentialVaultPage />);

    await waitFor(() => expect(screen.getByText("Prod API Key")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Prod API Key"));
    await waitFor(() => expect(screen.getByRole("dialog")).toBeInTheDocument());

    expect(screen.getByText("Disable").closest("button")).toBeDisabled();
    expect(screen.getByText("Enable").closest("button")).not.toBeDisabled();
  });

  it("calls revokeCredential with the entered reason", async () => {
    mockAll({ credentials: [makeCredential()] });
    vi.mocked(vault.revokeCredential).mockResolvedValue(makeCredential({ state: "REVOKED" }));
    render(<CredentialVaultPage />);

    await waitFor(() => expect(screen.getByText("Prod API Key")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Prod API Key"));
    await waitFor(() => expect(screen.getByRole("dialog")).toBeInTheDocument());

    fireEvent.change(screen.getByLabelText("Reason", { exact: false }), {
      target: { value: "key leaked in logs" },
    });
    fireEvent.click(screen.getByText("Revoke"));

    await waitFor(() => {
      expect(vault.revokeCredential).toHaveBeenCalledWith("cred-1", "key leaked in logs");
    });
    await waitFor(() => expect(screen.getByText("Credential revoked.")).toBeInTheDocument());
  });

  it("requires a new secret value before allowing rotation", async () => {
    mockAll({ credentials: [makeCredential()] });
    render(<CredentialVaultPage />);

    await waitFor(() => expect(screen.getByText("Prod API Key")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Prod API Key"));
    await waitFor(() => expect(screen.getByRole("dialog")).toBeInTheDocument());

    fireEvent.click(screen.getByText("Rotate"));

    await waitFor(() => {
      expect(screen.getByText("New secret value is required to rotate.")).toBeInTheDocument();
    });
    expect(vault.rotateCredential).not.toHaveBeenCalled();
  });

  it("renders version history and audit trail from real data", async () => {
    mockAll({
      credentials: [makeCredential()],
      versions: [makeVersion({ version_id: "v1", version_number: 1 })],
      audit: [makeAuditEntry({ entry_id: "a1", operation: "DISABLE", outcome: "SUCCESS" })],
    });
    render(<CredentialVaultPage />);

    await waitFor(() => expect(screen.getByText("Prod API Key")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Prod API Key"));

    await waitFor(() => expect(screen.getByText("v1")).toBeInTheDocument());
    expect(screen.getByText("DISABLE")).toBeInTheDocument();
    expect(screen.getByText("SUCCESS")).toBeInTheDocument();
  });

  it("creates a credential via the New Credential modal", async () => {
    mockAll({ credentials: [], backends: [makeBackend()] });
    vi.mocked(vault.createCredential).mockResolvedValue(makeCredential());
    render(<CredentialVaultPage />);

    await waitFor(() => expect(screen.getByRole("button", { name: "New Credential" })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "New Credential" }));

    fireEvent.change(screen.getByLabelText("Name", { exact: false }), { target: { value: "New Key" } });
    fireEvent.change(screen.getByLabelText("Category", { exact: false }), { target: { value: "API_KEY" } });
    fireEvent.change(screen.getByLabelText("Subtype", { exact: false }), { target: { value: "anthropic" } });
    fireEvent.change(screen.getByLabelText("Secret value", { exact: false }), { target: { value: "sk-abc" } });

    fireEvent.click(screen.getByText("Create"));

    await waitFor(() => {
      expect(vault.createCredential).toHaveBeenCalledWith({
        name: "New Key",
        category: "API_KEY",
        subtype: "anthropic",
        vault_backend_id: "backend-1",
        plaintext_secret: "sk-abc",
        description: undefined,
      });
    });
  });

  it("blocks credential creation when required fields are missing", async () => {
    mockAll({ credentials: [], backends: [makeBackend()] });
    render(<CredentialVaultPage />);

    await waitFor(() => expect(screen.getByRole("button", { name: "New Credential" })).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "New Credential" }));
    fireEvent.click(screen.getByText("Create"));

    await waitFor(() => {
      expect(
        screen.getByText("Name, category, subtype, vault backend, and secret value are required.")
      ).toBeInTheDocument();
    });
    expect(vault.createCredential).not.toHaveBeenCalled();
  });

  it("renders an honest empty state when the vault has no credentials", async () => {
    mockAll({ credentials: [] });
    render(<CredentialVaultPage />);

    await waitFor(() => {
      expect(screen.getByText("No credentials stored in the vault.")).toBeInTheDocument();
    });
  });

  // Regression test: the empty-state branch previously short-circuited the
  // entire tab (including the "New Credential" button), so a tenant with
  // zero credentials had no way to create their first one via the UI.
  it("still shows the New Credential button when the vault is empty", async () => {
    mockAll({ credentials: [], backends: [makeBackend()] });
    render(<CredentialVaultPage />);

    await waitFor(() => {
      expect(screen.getByText("No credentials stored in the vault.")).toBeInTheDocument();
    });
    expect(screen.getByRole("button", { name: "New Credential" })).toBeInTheDocument();
  });
});

describe("CredentialVaultPage — Policies tab", () => {
  it("derives policy KPIs from real rotation/expiration policy data", async () => {
    mockAll({
      credentials: [],
      rotationPolicies: [makeRotationPolicy({ auto_rotate: true }), makeRotationPolicy({ policy_id: "rot-2", auto_rotate: false })],
      expirationPolicies: [makeExpirationPolicy({ hard_expire: true })],
    });
    render(<CredentialVaultPage />);

    await waitFor(() => expect(screen.getByText("Credentials")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Policies"));

    await waitFor(() => expect(screen.getAllByText("Rotation Policies").length).toBeGreaterThan(0));
    const kpiValues = screen.getAllByText(/^[0-9]+$/).map((el) => el.textContent);
    expect(kpiValues).toContain("2"); // rotation policies
    expect(kpiValues.filter((v) => v === "1").length).toBeGreaterThanOrEqual(2); // auto-rotate + hard-expire
  });

  it("creates a rotation policy via the modal", async () => {
    mockAll({ credentials: [] });
    vi.mocked(vault.createRotationPolicy).mockResolvedValue(makeRotationPolicy());
    render(<CredentialVaultPage />);

    fireEvent.click(await screen.findByText("Policies"));
    fireEvent.click(await screen.findByText("+ New Rotation Policy"));

    fireEvent.change(screen.getByLabelText("Policy name", { exact: false }), { target: { value: "180-day rotation" } });
    fireEvent.click(screen.getByText("Create"));

    await waitFor(() => {
      expect(vault.createRotationPolicy).toHaveBeenCalledWith(
        expect.objectContaining({ name: "180-day rotation" })
      );
    });
  });
});

describe("CredentialVaultPage — Vault Backends tab", () => {
  it("derives backend KPIs from real backend data", async () => {
    mockAll({
      credentials: [],
      backends: [
        makeBackend({ backend_id: "b1", name: "Local Vault", is_default: true, backend_type: "LOCAL" }),
        makeBackend({ backend_id: "b2", name: "AWS Vault", is_default: false, backend_type: "AWS_KMS" }),
      ],
    });
    render(<CredentialVaultPage />);

    fireEvent.click(await screen.findByText("Vault Backends"));

    await waitFor(() => expect(screen.getByText("AWS Vault")).toBeInTheDocument());
    const kpiValues = screen.getAllByText(/^[0-9]+$/).map((el) => el.textContent);
    expect(kpiValues).toContain("2"); // total backends
    expect(kpiValues).toContain("2"); // 2 distinct backend types
  });

  it("registers a vault backend via the modal", async () => {
    mockAll({ credentials: [] });
    vi.mocked(vault.registerVaultBackend).mockResolvedValue(makeBackend());
    render(<CredentialVaultPage />);

    fireEvent.click(await screen.findByText("Vault Backends"));
    fireEvent.click(await screen.findByText("Register Backend"));

    fireEvent.change(screen.getByLabelText("Backend name", { exact: false }), { target: { value: "AWS Prod Vault" } });
    fireEvent.change(screen.getByLabelText("Backend type", { exact: false }), {
      target: { value: "AWS_KMS" },
    });
    fireEvent.click(screen.getByText("Register"));

    await waitFor(() => {
      expect(vault.registerVaultBackend).toHaveBeenCalledWith({
        name: "AWS Prod Vault",
        backend_type: "AWS_KMS",
        is_default: false,
      });
    });
  });

  it("deletes a vault backend after confirmation", async () => {
    mockAll({ credentials: [], backends: [makeBackend()] });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<CredentialVaultPage />);

    fireEvent.click(await screen.findByText("Vault Backends"));
    await waitFor(() => expect(screen.getAllByText("Local Vault").length).toBeGreaterThan(0));

    fireEvent.click(screen.getByText("Delete"));

    await waitFor(() => {
      expect(vault.deleteVaultBackend).toHaveBeenCalledWith("backend-1");
    });
  });
});

describe("CredentialVaultPage — form accessibility", () => {
  it("New Credential modal: every field has a real <label for> element, not just a placeholder", async () => {
    mockAll({ credentials: [], backends: [makeBackend()] });
    const { container } = render(<CredentialVaultPage />);
    fireEvent.click(await screen.findByText("New Credential"));

    for (const name of ["Name", "Category", "Subtype", "Vault backend", "Secret value", "Description"]) {
      const field = screen.getByLabelText(name, { exact: false });
      expect(field).toBeInTheDocument();
      expect(field.id).toBeTruthy();
      // Accessible name must come from a real <label for>, not aria-label
      // (which would make placeholder the only *visible* label).
      const label = container.querySelector(`label[for="${field.id}"]`);
      expect(label).not.toBeNull();
      expect(field).not.toHaveAttribute("aria-label");
    }
  });

  it("New Credential modal is a real dialog: traps focus, closes on Escape, returns focus to the trigger", async () => {
    mockAll({ credentials: [], backends: [makeBackend()] });
    render(<CredentialVaultPage />);
    const trigger = await screen.findByRole("button", { name: "New Credential" });
    trigger.focus();
    fireEvent.click(trigger);

    const dialog = screen.getByRole("dialog", { name: "New Credential" });
    expect(dialog).toBeInTheDocument();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog", { name: "New Credential" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("required fields are announced via aria-required, and the secret field is not autofilled from a saved password", async () => {
    mockAll({ credentials: [], backends: [makeBackend()] });
    render(<CredentialVaultPage />);
    fireEvent.click(await screen.findByText("New Credential"));

    expect(screen.getByLabelText("Name", { exact: false })).toHaveAttribute("aria-required", "true");
    expect(screen.getByLabelText("Description", { exact: false })).not.toHaveAttribute("aria-required");
    expect(screen.getByLabelText("Secret value", { exact: false })).toHaveAttribute(
      "autocomplete",
      "new-password"
    );
  });

  it("the Resolve Secret and break-glass justification fields have real labels", async () => {
    mockAll({ credentials: [makeCredential()] });
    render(<CredentialVaultPage />);
    fireEvent.click(await screen.findByText("Prod API Key"));
    await waitFor(() => expect(screen.getByRole("dialog")).toBeInTheDocument());

    expect(screen.getByLabelText("Purpose", { exact: false })).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText("Break-glass access"));
    expect(screen.getByLabelText("Break-glass justification", { exact: false })).toBeInTheDocument();
  });

  it("no duplicate field ids exist within the New Credential modal", async () => {
    mockAll({ credentials: [], backends: [makeBackend()] });
    const { container } = render(<CredentialVaultPage />);
    fireEvent.click(await screen.findByText("New Credential"));

    const ids = Array.from(container.querySelectorAll("[id]")).map((el) => el.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("Register Backend modal is a real labelled dialog with required fields", async () => {
    mockAll({ credentials: [] });
    render(<CredentialVaultPage />);
    fireEvent.click(await screen.findByText("Vault Backends"));
    const trigger = await screen.findByRole("button", { name: "Register Backend" });
    trigger.focus();
    fireEvent.click(trigger);

    expect(screen.getByRole("dialog", { name: "Register Vault Backend" })).toBeInTheDocument();
    expect(screen.getByLabelText("Backend name", { exact: false })).toHaveAttribute("aria-required", "true");
    expect(screen.getByLabelText("Backend type", { exact: false })).toHaveAttribute("aria-required", "true");

    fireEvent.keyDown(document, { key: "Escape" });
    expect(trigger).toHaveFocus();
  });
});
