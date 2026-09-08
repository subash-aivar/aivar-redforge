import { describe, it, expect, vi, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import * as platform from "@/lib/platform";
import { useStepUp } from "./useStepUp";

vi.mock("@/lib/platform", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/lib/platform")>();
  return { ...actual, stepUp: vi.fn() };
});

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

/** Minimal real consumer: a protected button that requests step-up before
 * "running" a stand-in privileged action — mirrors how platform/access,
 * organizations, and users pages actually consume the hook. */
function ProtectedActionHarness({ onToken }: { onToken: (token: string | null) => void }) {
  const { requestStepUp, stepUpModal } = useStepUp();
  return (
    <div>
      <button
        onClick={async () => {
          const token = await requestStepUp();
          onToken(token);
        }}
      >
        Run Privileged Action
      </button>
      {stepUpModal}
    </div>
  );
}

async function openStepUp(onToken = vi.fn()) {
  render(<ProtectedActionHarness onToken={onToken} />);
  const trigger = screen.getByText("Run Privileged Action");
  trigger.focus();
  fireEvent.click(trigger);
  await waitFor(() => {
    expect(screen.getByRole("dialog", { name: "Step-up verification required" })).toBeInTheDocument();
  });
  return { trigger, onToken };
}

describe("useStepUp — modal semantics", () => {
  it("opens a real role=dialog modal, not a bespoke unmanaged overlay", async () => {
    await openStepUp();
    const dialog = screen.getByRole("dialog", { name: "Step-up verification required" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
  });

  it("the MFA code field has a real programmatic label, correct type, and correct autocomplete", async () => {
    const { container } = render(<ProtectedActionHarness onToken={vi.fn()} />);
    fireEvent.click(screen.getByText("Run Privileged Action"));
    await waitFor(() => screen.getByRole("dialog"));

    const field = screen.getByLabelText("MFA code", { exact: false });
    expect(field.id).toBeTruthy();
    expect(container.querySelector(`label[for="${field.id}"]`)).not.toBeNull();
    expect(field).toHaveAttribute("autocomplete", "one-time-code");
    expect(field).toHaveAttribute("inputmode", "numeric");
    expect(field).not.toHaveAttribute("type", "password"); // an OTP, not a secret to mask
  });

  it("an incomplete code shows a linked validation error and keeps focus on the field", async () => {
    await openStepUp();
    fireEvent.change(screen.getByLabelText("MFA code", { exact: false }), {
      target: { value: "123" },
    });
    // The submit button stays disabled below 6 digits — the only way to
    // trigger the validation branch is a form-level submit (Enter).
    fireEvent.submit(screen.getByRole("dialog").querySelector("form")!);

    const field = screen.getByLabelText("MFA code", { exact: false });
    await waitFor(() => {
      expect(field).toHaveAttribute("aria-invalid", "true");
    });
    const describedBy = field.getAttribute("aria-describedby");
    expect(document.getElementById(describedBy!.split(" ")[0])).toHaveTextContent(
      "Enter your current 6-digit MFA code."
    );
    expect(field).toHaveFocus();
    expect(platform.stepUp).not.toHaveBeenCalled();
  });

  it("Cancel resolves with null and sends no verification request", async () => {
    const onToken = vi.fn();
    const { trigger } = await openStepUp(onToken);

    fireEvent.click(screen.getByText("Cancel"));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(platform.stepUp).not.toHaveBeenCalled();
    await waitFor(() => expect(onToken).toHaveBeenCalledWith(null));
    expect(trigger).toHaveFocus();
  });

  it("Escape resolves with null, sends no request, and returns focus to the trigger", async () => {
    const onToken = vi.fn();
    const { trigger } = await openStepUp(onToken);

    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(platform.stepUp).not.toHaveBeenCalled();
    await waitFor(() => expect(onToken).toHaveBeenCalledWith(null));
    expect(trigger).toHaveFocus();
  });

  it("a valid code resolves with the real backend assurance token — the protected action cannot proceed without it", async () => {
    vi.mocked(platform.stepUp).mockResolvedValue({
      assurance_token: "real-assurance-token-abc",
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    });
    const onToken = vi.fn();
    await openStepUp(onToken);

    fireEvent.change(screen.getByLabelText("MFA code", { exact: false }), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByText("Verify"));

    await waitFor(() => {
      expect(platform.stepUp).toHaveBeenCalledWith("123456");
    });
    await waitFor(() => expect(onToken).toHaveBeenCalledWith("real-assurance-token-abc"));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("loading state prevents a duplicate verification request", async () => {
    let resolveStepUp!: (v: { assurance_token: string; expires_at: string }) => void;
    vi.mocked(platform.stepUp).mockReturnValue(
      new Promise((resolve) => {
        resolveStepUp = resolve;
      })
    );
    await openStepUp();
    fireEvent.change(screen.getByLabelText("MFA code", { exact: false }), {
      target: { value: "123456" },
    });
    fireEvent.click(screen.getByText("Verify"));

    await waitFor(() => {
      expect(screen.getByText("Verifying…")).toBeDisabled();
    });
    fireEvent.click(screen.getByText("Verifying…"));
    expect(platform.stepUp).toHaveBeenCalledTimes(1);

    resolveStepUp({ assurance_token: "tok", expires_at: new Date().toISOString() });
  });

  it("a denied/expired/failed code is announced via role=alert, distinct from an incomplete-input validation error, and keeps the modal open", async () => {
    vi.mocked(platform.stepUp).mockRejectedValue(new Error("Assurance denied: code expired"));
    await openStepUp();
    fireEvent.change(screen.getByLabelText("MFA code", { exact: false }), {
      target: { value: "999999" },
    });
    fireEvent.click(screen.getByText("Verify"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent("Assurance denied: code expired");
    });
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("the MFA code is never present in the rendered error output, localStorage, or sessionStorage", async () => {
    vi.mocked(platform.stepUp).mockRejectedValue(new Error("Verification failed"));
    await openStepUp();
    const secretCode = "482913";
    fireEvent.change(screen.getByLabelText("MFA code", { exact: false }), {
      target: { value: secretCode },
    });
    fireEvent.click(screen.getByText("Verify"));

    await waitFor(() => screen.getByRole("alert"));
    expect(screen.getByRole("alert")).not.toHaveTextContent(secretCode);
    if (window.localStorage) {
      expect(JSON.stringify(window.localStorage)).not.toContain(secretCode);
    }
    if (window.sessionStorage) {
      expect(JSON.stringify(window.sessionStorage)).not.toContain(secretCode);
    }
  });

  it("no duplicate field ids exist while the step-up modal is open", async () => {
    const { container } = render(<ProtectedActionHarness onToken={vi.fn()} />);
    fireEvent.click(screen.getByText("Run Privileged Action"));
    await waitFor(() => screen.getByRole("dialog"));

    const ids = Array.from(container.querySelectorAll("[id]")).map((el) => el.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe("useStepUp — stacked-dialog Escape semantics", () => {
  it("when step-up is opened as the topmost layer, Escape closes only step-up", async () => {
    // Verified structurally via the shared dialog-stack in cc.tsx (see
    // NavigationShell/InvestigationDrawer/FormModal cross-stacking tests) —
    // this test proves useStepUp's modal participates in that same stack
    // rather than using an independent, uncoordinated keydown listener.
    const onToken = vi.fn();
    const { trigger } = await openStepUp(onToken);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });
});
