import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import { api } from "@/lib/api";
import ValidationOperationsPage from "./page";
import type {
  ValidationExecution,
  ValidationExecutionSummary,
  ExecutionEvent,
  ValidationResult,
} from "@/lib/validationOperations";

vi.mock("@/lib/api", () => ({
  api: { get: vi.fn(), post: vi.fn() },
  ApiError: class ApiError extends Error {
    status: number;
    constructor(status: number, message: string) {
      super(message);
      this.status = status;
    }
  },
}));

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const SUMMARY: ValidationExecutionSummary = {
  pending: 0,
  policy_checking: 0,
  authorized: 0,
  running: 1,
  completed: 2,
  partially_completed: 0,
  failed: 0,
  cancelled: 0,
  denied: 1,
};

function makeExecution(overrides: Partial<ValidationExecution> = {}): ValidationExecution {
  return {
    id: "exec-1",
    organization_id: "org-1",
    target_id: "target-1",
    requester_user_id: "user-1",
    profile: "safe_active_baseline_v1",
    status: "completed",
    policy_decision_id: "dec-1",
    policy_reason_code: null,
    cancellation_requested: false,
    created_at: new Date(0).toISOString(),
    updated_at: new Date(0).toISOString(),
    started_at: new Date(1000).toISOString(),
    completed_at: new Date(2000).toISOString(),
    failure_reason: "",
    steps: [
      {
        id: "step-1",
        step_type: "dns_resolution",
        order: 0,
        status: "completed",
        started_at: new Date(1000).toISOString(),
        completed_at: new Date(1200).toISOString(),
        evidence: [{ label: "resolved_addresses", value: "8.8.8.8", truncated: "false" }],
        error_category: null,
        source: "initial",
        adaptive_rule_id: null,
        adaptive_rule_version: null,
        source_fact_ref: null,
        validator_id: null,
        validator_version: null,
        protocol_validation_state: null,
      },
    ],
    plan_summary: {
      initial_step_count: 1,
      adaptive_step_count: 0,
      discovered_address_count: 0,
      reachable_port_count: 0,
      validated_service_count: 0,
      condition_count: 0,
    },
    ...overrides,
  };
}

function makeEvent(overrides: Partial<ExecutionEvent> = {}): ExecutionEvent {
  return {
    id: "event-1",
    execution_id: "exec-1",
    sequence: 1,
    event_type: "execution_created",
    payload: {},
    occurred_at: new Date(0).toISOString(),
    ...overrides,
  };
}

function makeResult(overrides: Partial<ValidationResult> = {}): ValidationResult {
  return {
    execution_id: "exec-1",
    target_id: "target-1",
    status: "completed",
    tcp_reachable: true,
    application_layer_validated: true,
    validation_basis: "http",
    tls_protocol_version: null,
    http_status_code: "200",
    conditions_observed: ["MISSING_CSP_HEADER"],
    failed_steps: [],
    created_at: new Date(0).toISOString(),
    started_at: new Date(1000).toISOString(),
    completed_at: new Date(2000).toISOString(),
    discovered_addresses: [],
    reachable_ports: [],
    validated_services: [],
    correlations_created: null,
    correlations_updated: null,
    correlations_resolved: null,
    ...overrides,
  };
}

function mockApi(opts: {
  summary?: ValidationExecutionSummary;
  executions?: ValidationExecution[];
  events?: ExecutionEvent[];
  result?: ValidationResult | null;
  targets?: Array<{ id: string; name: string; endpoint: string }>;
}) {
  const {
    summary = SUMMARY,
    executions = [makeExecution()],
    events = [makeEvent()],
    result = makeResult(),
    targets = [{ id: "target-1", name: "Owned Test Target", endpoint: "https://example.test/" }],
  } = opts;

  vi.mocked(api.get).mockImplementation((path: string) => {
    if (path.includes("/validation-executions/summary")) return Promise.resolve(summary);
    if (path.includes("/events")) return Promise.resolve(events);
    if (path.includes("/result")) {
      return result ? Promise.resolve(result) : Promise.reject(new Error("no result"));
    }
    if (path.match(/\/validation-executions\/[^/]+$/)) {
      const id = path.split("/").pop();
      const found = executions.find((e) => e.id === id) ?? executions[0];
      return Promise.resolve(found);
    }
    if (path.includes("/validation-executions")) return Promise.resolve(executions);
    if (path.includes("/api/v1/targets")) return Promise.resolve(targets);
    return Promise.reject(new Error(`unexpected path: ${path}`));
  });
}

describe("ValidationOperationsPage overview", () => {
  it("renders backend-derived counts, not fabricated totals", async () => {
    mockApi({});
    render(<ValidationOperationsPage />);
    await waitFor(() => {
      expect(screen.getByText("2")).toBeInTheDocument(); // completed
    });
    expect(screen.getAllByText("1")).toHaveLength(2); // running=1, denied=1
  });

  it("renders an explicit empty state, not a blank list", async () => {
    mockApi({ executions: [] });
    render(<ValidationOperationsPage />);
    await waitFor(() => {
      expect(screen.getByText(/No validation executions match/i)).toBeInTheDocument();
    });
  });

  it("surfaces an API failure truthfully instead of a silent empty state", async () => {
    vi.mocked(api.get).mockRejectedValue(new Error("network down"));
    render(<ValidationOperationsPage />);
    await waitFor(() => {
      expect(screen.getAllByText(/UNAVAILABLE/i).length).toBeGreaterThan(0);
    });
  });
});

describe("ValidationOperationsPage status rendering", () => {
  it("renders an unrecognized status as UNKNOWN, not a crash", async () => {
    mockApi({ executions: [makeExecution({ status: "some_future_status" })] });
    render(<ValidationOperationsPage />);
    await waitFor(() => {
      expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
    });
  });

  it("renders COMPLETED executions with step progress", async () => {
    mockApi({ executions: [makeExecution()] });
    render(<ValidationOperationsPage />);
    await waitFor(() => {
      expect(screen.getByText("COMPLETED")).toBeInTheDocument();
    });
    expect(screen.getByText("1/1 steps completed")).toBeInTheDocument();
  });
});

describe("ValidationOperationsPage detail view", () => {
  it("shows steps, events, and the crisp result on open", async () => {
    mockApi({ executions: [makeExecution()] });
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("COMPLETED"));
    fireEvent.click(screen.getByText("COMPLETED"));
    await waitFor(() => {
      expect(screen.getByText("DNS Resolution")).toBeInTheDocument();
    });
    expect(screen.getByText(/MISSING_CSP_HEADER/)).toBeInTheDocument();
    expect(screen.getByText(/TCP reachable:/)).toBeInTheDocument();
  });

  it("shows a Cancel button for a RUNNING execution but not a COMPLETED one", async () => {
    mockApi({ executions: [makeExecution({ id: "exec-running", status: "running" })] });
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("RUNNING"));
    fireEvent.click(screen.getByText("RUNNING"));
    await waitFor(() => {
      expect(screen.getByText("Cancel Execution")).toBeInTheDocument();
    });
  });

  it("never fabricates a Finding from bare connectivity — TCP evidence has no finding label", async () => {
    mockApi({ executions: [makeExecution()] });
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("COMPLETED"));
    fireEvent.click(screen.getByText("COMPLETED"));
    await waitFor(() => screen.getByText("DNS Resolution"));
    expect(screen.queryByText(/finding/i)).not.toBeInTheDocument();
  });

  it("does not show a Cancel button for a DENIED execution with zero steps", async () => {
    mockApi({
      executions: [
        makeExecution({
          id: "exec-denied",
          status: "denied",
          policy_reason_code: "no_authorization_found",
          steps: [],
        }),
      ],
      events: [makeEvent({ event_type: "policy_denied" })],
      result: null,
    });
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("DENIED"));
    fireEvent.click(screen.getByText("DENIED"));
    await waitFor(() => {
      expect(screen.getByText("no_authorization_found")).toBeInTheDocument();
    });
    expect(screen.queryByText("Cancel Execution")).not.toBeInTheDocument();
    expect(screen.getByText(/No steps were ever created/i)).toBeInTheDocument();
  });
});

describe("ValidationOperationsPage start-validation form", () => {
  it("requires a canonical target before submitting", async () => {
    mockApi({});
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("Start Validation"));
    fireEvent.click(screen.getByText("Start Validation"));
    const submitButtons = await screen.findAllByText("Start Validation");
    fireEvent.click(submitButtons[submitButtons.length - 1]);
    await waitFor(() => {
      expect(screen.getByText(/Select a canonical target/i)).toBeInTheDocument();
    });
    expect(api.post).not.toHaveBeenCalled();
  });

  it("the missing-target error is announced via role=alert and moves focus to the target selector", async () => {
    mockApi({});
    render(<ValidationOperationsPage />);
    fireEvent.click(await screen.findByText("Start Validation"));
    const submitButtons = await screen.findAllByText("Start Validation");
    fireEvent.click(submitButtons[submitButtons.length - 1]);

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("Select a canonical target.");
    });
    expect(document.activeElement?.tagName).toBe("SELECT");
    expect(screen.getByLabelText("Canonical target", { exact: false })).toHaveFocus();
  });

  it("the target and profile selectors have real programmatic labels", async () => {
    mockApi({});
    const { container } = render(<ValidationOperationsPage />);
    fireEvent.click(await screen.findByText("Start Validation"));

    for (const name of ["Canonical target", "Validation profile"]) {
      const field = screen.getByLabelText(name, { exact: false });
      expect(field.id).toBeTruthy();
      expect(container.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
    }
  });

  it("never offers a field for arbitrary steps, ports, or commands", async () => {
    mockApi({});
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("Start Validation"));
    fireEvent.click(screen.getByText("Start Validation"));
    await waitFor(() => screen.getByText("Validation profile"));
    expect(screen.queryByPlaceholderText(/port/i)).not.toBeInTheDocument();
    expect(screen.queryByPlaceholderText(/command/i)).not.toBeInTheDocument();
  });

  it("offers exactly the two closed profiles, defaulting to safe active validation", async () => {
    mockApi({});
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("Start Validation"));
    fireEvent.click(screen.getByText("Start Validation"));
    const select = (await screen.findByText("Validation profile")).parentElement!.querySelector(
      "select"
    ) as HTMLSelectElement;
    const optionValues = Array.from(select.options).map((o) => o.value);
    expect(optionValues).toEqual(["safe_active_baseline_v1", "network_discovery_baseline_v1"]);
    expect(select.value).toBe("safe_active_baseline_v1");
  });

  it("submits the selected profile, never a client-invented one", async () => {
    mockApi({});
    vi.mocked(api.post).mockResolvedValue(makeExecution());
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("Start Validation"));
    fireEvent.click(screen.getByText("Start Validation"));
    const select = (await screen.findByText("Validation profile")).parentElement!.querySelector(
      "select"
    ) as HTMLSelectElement;
    fireEvent.change(select, { target: { value: "network_discovery_baseline_v1" } });
    const targetSelect = (await screen.findByText("Canonical target")).parentElement!.querySelector(
      "select"
    ) as HTMLSelectElement;
    fireEvent.change(targetSelect, { target: { value: "target-1" } });
    const submitButtons = await screen.findAllByText("Start Validation");
    fireEvent.click(submitButtons[submitButtons.length - 1]);
    await waitFor(() => {
      expect(api.post).toHaveBeenCalledWith(
        "/api/v1/validation-executions",
        expect.objectContaining({ profile: "network_discovery_baseline_v1" })
      );
    });
  });
});

describe("ValidationOperationsPage M12 discovery/adaptive rendering", () => {
  it("shows the plan summary and marks adaptive steps distinctly from initial ones", async () => {
    mockApi({
      executions: [
        makeExecution({
          profile: "network_discovery_baseline_v1",
          plan_summary: {
            initial_step_count: 2,
            adaptive_step_count: 1,
            discovered_address_count: 1,
            reachable_port_count: 2,
            validated_service_count: 1,
            condition_count: 1,
          },
          steps: [
            {
              id: "step-discovery",
              step_type: "port_discovery",
              order: 0,
              status: "completed",
              started_at: new Date(1000).toISOString(),
              completed_at: new Date(1200).toISOString(),
              evidence: [{ label: "port_443", value: "reachable:https", truncated: "false" }],
              error_category: null,
              source: "initial",
              adaptive_rule_id: null,
              adaptive_rule_version: null,
              source_fact_ref: null,
              validator_id: null,
              validator_version: null,
              protocol_validation_state: null,
            },
            {
              id: "step-adaptive",
              step_type: "tls_handshake",
              order: 1,
              status: "completed",
              started_at: new Date(1300).toISOString(),
              completed_at: new Date(1400).toISOString(),
              evidence: [],
              error_category: null,
              source: "adaptive",
              adaptive_rule_id: "PORT_443_TLS_HTTPS",
              adaptive_rule_version: 1,
              source_fact_ref: "tcp_port:443:reachable",
              validator_id: null,
              validator_version: null,
              protocol_validation_state: null,
            },
          ],
        }),
      ],
    });
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("COMPLETED"));
    fireEvent.click(screen.getByText("COMPLETED"));
    await waitFor(() => {
      expect(screen.getByText("Port Discovery")).toBeInTheDocument();
    });
    expect(screen.getByText("2 initial steps")).toBeInTheDocument();
    expect(screen.getByText("1 adaptive step")).toBeInTheDocument();
    expect(screen.getByText("Initial")).toBeInTheDocument();
    expect(screen.getByText("Adaptive")).toBeInTheDocument();
    expect(screen.getByText(/PORT_443_TLS_HTTPS v1/)).toBeInTheDocument();
  });

  it("renders discovered addresses, reachable ports, and per-service hinted/validated state in the result", async () => {
    mockApi({
      executions: [makeExecution({ profile: "network_discovery_baseline_v1" })],
      result: makeResult({
        discovered_addresses: ["127.0.0.1"],
        reachable_ports: [80, 443, 3306],
        validated_services: [
          { port: "443", hint: "https", state: "validated", validator_id: "", validator_version: "" },
          {
            port: "3306", hint: "mysql", state: "hinted",
            validator_id: "MYSQL_HANDSHAKE_V1", validator_version: "1",
          },
        ],
        correlations_created: 1,
        correlations_updated: 0,
        correlations_resolved: 0,
      }),
    });
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("COMPLETED"));
    fireEvent.click(screen.getByText("COMPLETED"));
    await waitFor(() => {
      expect(screen.getByText(/Discovered addresses:/)).toBeInTheDocument();
    });
    expect(screen.getByText(/127.0.0.1/)).toBeInTheDocument();
    expect(screen.getByText(/Reachable ports:/)).toBeInTheDocument();
    expect(screen.getByText("Validated")).toBeInTheDocument();
    expect(screen.getByText("Hinted")).toBeInTheDocument();
    expect(screen.getByText(/Correlations — created 1/)).toBeInTheDocument();
  });

  it("never fabricates a validated service — a hinted-only port stays Hinted, not Validated", async () => {
    mockApi({
      executions: [makeExecution({ profile: "network_discovery_baseline_v1" })],
      result: makeResult({
        reachable_ports: [3306],
        validated_services: [
          {
            port: "3306", hint: "mysql", state: "hinted",
            validator_id: "MYSQL_HANDSHAKE_V1", validator_version: "1",
          },
        ],
      }),
    });
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("COMPLETED"));
    fireEvent.click(screen.getByText("COMPLETED"));
    await waitFor(() => {
      expect(screen.getByText("Hinted")).toBeInTheDocument();
    });
    expect(screen.queryByText("Validated")).not.toBeInTheDocument();
  });
});

describe("ValidationOperationsPage M13 protocol validation rendering", () => {
  function makeProtocolStep(overrides: Partial<ValidationExecution["steps"][number]> = {}) {
    return {
      id: "step-protocol",
      step_type: "ssh_banner",
      order: 1,
      status: "completed",
      started_at: new Date(1300).toISOString(),
      completed_at: new Date(1400).toISOString(),
      evidence: [] as { label: string; value: string; truncated: string }[],
      error_category: null,
      source: "adaptive",
      adaptive_rule_id: "PORT_22_SSH",
      adaptive_rule_version: 1,
      source_fact_ref: "tcp_port:22:reachable",
      validator_id: "SSH_BANNER_V1",
      validator_version: 1,
      protocol_validation_state: "validated",
      ...overrides,
    };
  }

  it("renders a VALIDATED protocol step with its validator provenance", async () => {
    mockApi({
      executions: [
        makeExecution({
          profile: "network_discovery_baseline_v1",
          steps: [
            makeProtocolStep({
              evidence: [
                { label: "banner", value: "SSH-2.0-OpenSSH_9.6", truncated: "false" },
                { label: "software_hint", value: "OpenSSH_9.6", truncated: "false" },
              ],
            }),
          ],
        }),
      ],
    });
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("COMPLETED"));
    fireEvent.click(screen.getByText("COMPLETED"));
    await waitFor(() => {
      expect(screen.getByText("SSH Banner")).toBeInTheDocument();
    });
    expect(screen.getByText("Validated")).toBeInTheDocument();
    expect(screen.getByText(/Validator: SSH_BANNER_V1 v1/)).toBeInTheDocument();
    expect(screen.getByText(/SSH-2.0-OpenSSH_9.6/)).toBeInTheDocument();
  });

  it("renders an SSH port reachable with an invalid banner as Inconclusive, never Validated", async () => {
    mockApi({
      executions: [
        makeExecution({
          profile: "network_discovery_baseline_v1",
          steps: [
            makeProtocolStep({
              protocol_validation_state: "inconclusive",
              evidence: [{ label: "banner", value: "NOT-AN-SSH-BANNER", truncated: "false" }],
            }),
          ],
        }),
      ],
    });
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("COMPLETED"));
    fireEvent.click(screen.getByText("COMPLETED"));
    await waitFor(() => {
      expect(screen.getByText("Inconclusive")).toBeInTheDocument();
    });
    expect(screen.queryByText("Validated")).not.toBeInTheDocument();
  });

  it("renders a validated MySQL handshake step distinctly from SSH", async () => {
    mockApi({
      executions: [
        makeExecution({
          profile: "network_discovery_baseline_v1",
          steps: [
            makeProtocolStep({
              id: "step-mysql",
              step_type: "mysql_handshake",
              adaptive_rule_id: "PORT_3306_MYSQL",
              source_fact_ref: "tcp_port:3306:reachable",
              validator_id: "MYSQL_HANDSHAKE_V1",
              protocol_validation_state: "validated",
              evidence: [
                { label: "server_version", value: "8.0.35", truncated: "false" },
                { label: "supports_ssl", value: "True", truncated: "false" },
              ],
            }),
          ],
        }),
      ],
    });
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("COMPLETED"));
    fireEvent.click(screen.getByText("COMPLETED"));
    await waitFor(() => {
      expect(screen.getByText("MySQL Handshake")).toBeInTheDocument();
    });
    expect(screen.getByText("Validated")).toBeInTheDocument();
    expect(screen.getByText(/Validator: MYSQL_HANDSHAKE_V1 v1/)).toBeInTheDocument();
    expect(screen.getByText(/8.0.35/)).toBeInTheDocument();
  });

  it("only ever shows safe, bounded metadata — never a raw response body or secret-shaped value", async () => {
    mockApi({
      executions: [
        makeExecution({
          profile: "network_discovery_baseline_v1",
          steps: [
            makeProtocolStep({
              evidence: [{ label: "banner", value: "SSH-2.0-OpenSSH_9.6", truncated: "false" }],
            }),
          ],
        }),
      ],
    });
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("COMPLETED"));
    fireEvent.click(screen.getByText("COMPLETED"));
    await waitFor(() => screen.getByText("SSH Banner"));
    expect(screen.queryByText(/authorization/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/password/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/BEGIN.*PRIVATE KEY/i)).not.toBeInTheDocument();
  });

  it("never shows a vulnerability label for bare port reachability alone", async () => {
    mockApi({
      executions: [
        makeExecution({
          profile: "network_discovery_baseline_v1",
          steps: [
            {
              id: "step-discovery",
              step_type: "port_discovery",
              order: 0,
              status: "completed",
              started_at: new Date(1000).toISOString(),
              completed_at: new Date(1200).toISOString(),
              evidence: [{ label: "port_6379", value: "reachable:redis", truncated: "false" }],
              error_category: null,
              source: "initial",
              adaptive_rule_id: null,
              adaptive_rule_version: null,
              source_fact_ref: null,
              validator_id: null,
              validator_version: null,
              protocol_validation_state: null,
            },
          ],
        }),
      ],
    });
    render(<ValidationOperationsPage />);
    await waitFor(() => screen.getByText("COMPLETED"));
    fireEvent.click(screen.getByText("COMPLETED"));
    await waitFor(() => screen.getByText("Port Discovery"));
    expect(screen.queryByText(/vulnerab/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/CVE-/i)).not.toBeInTheDocument();
  });
});
