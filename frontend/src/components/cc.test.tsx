import { useState } from "react";
import { describe, expect, it, vi, afterEach } from "vitest";
import { cleanup, render, screen, fireEvent } from "@testing-library/react";
import {
  DataConsole,
  EmptyRow,
  ErrorRow,
  FormField,
  FormModal,
  InvestigationDrawer,
  LoadingRow,
} from "@/components/cc";

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("InvestigationDrawer", () => {
  it("renders as an accessible dialog and focuses the close button on open", () => {
    render(
      <InvestigationDrawer
        open
        onClose={vi.fn()}
        title="Correlation detail"
        fields={[{ label: "Status", value: "Active" }]}
      />
    );
    const dialog = screen.getByRole("dialog", { name: "Correlation detail" });
    expect(dialog).toHaveAttribute("aria-modal", "true");
    expect(screen.getByRole("button", { name: "Close" })).toHaveFocus();
  });

  it("closes on Escape", () => {
    const onClose = vi.fn();
    render(
      <InvestigationDrawer
        open
        onClose={onClose}
        title="Correlation detail"
        fields={[{ label: "Status", value: "Active" }]}
      />
    );
    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalled();
  });

  it("returns focus to the previously focused element on close", () => {
    function Harness() {
      const [open, setOpen] = useState(false);
      return (
        <>
          <button onClick={() => setOpen(true)}>Open drawer</button>
          <InvestigationDrawer
            open={open}
            onClose={() => setOpen(false)}
            title="Correlation detail"
            fields={[{ label: "Status", value: "Active" }]}
          />
        </>
      );
    }
    render(<Harness />);
    const trigger = screen.getByRole("button", { name: "Open drawer" });
    trigger.focus();
    fireEvent.click(trigger);
    fireEvent.keyDown(document, { key: "Escape" });
    expect(trigger).toHaveFocus();
  });

  it("renders a Copy ID quick action only when entityId is supplied — never a fabricated one", () => {
    const { rerender } = render(
      <InvestigationDrawer
        open
        onClose={vi.fn()}
        title="Correlation detail"
        entityId="corr-42"
        fields={[{ label: "Status", value: "Active" }]}
      />
    );
    expect(screen.getByText(/corr-42/)).toBeInTheDocument();

    rerender(
      <InvestigationDrawer
        open
        onClose={vi.fn()}
        title="Correlation detail"
        fields={[{ label: "Status", value: "Active" }]}
      />
    );
    expect(screen.queryByText(/copy/i)).not.toBeInTheDocument();
  });
});

describe("shared state rows announce to assistive technology", () => {
  it("LoadingRow exposes role=status so a screen reader announces it", () => {
    render(<LoadingRow label="Loading targets…" />);
    expect(screen.getByRole("status")).toHaveTextContent("Loading targets…");
  });

  it("EmptyRow exposes role=status", () => {
    render(<EmptyRow label="No targets yet." />);
    expect(screen.getByRole("status")).toHaveTextContent("No targets yet.");
  });

  it("ErrorRow exposes role=alert (implicit assertive live region)", () => {
    render(<ErrorRow message="Failed to load targets." />);
    expect(screen.getByRole("alert")).toHaveTextContent("Failed to load targets.");
  });
});

describe("DataConsole row-click keyboard operability", () => {
  interface Row {
    id: string;
    name: string;
  }
  const columns = [{ key: "name", header: "Name", render: (r: Row) => r.name }];
  const rows: Row[] = [{ id: "r1", name: "Row One" }, { id: "r2", name: "Row Two" }];

  it("clickable rows are focusable and Enter activates onRowClick", () => {
    const onRowClick = vi.fn();
    render(<DataConsole columns={columns} rows={rows} rowKey={(r) => r.id} onRowClick={onRowClick} />);
    const row = screen.getByText("Row One").closest("tr")!;
    expect(row).toHaveAttribute("tabindex", "0");
    row.focus();
    fireEvent.keyDown(row, { key: "Enter" });
    expect(onRowClick).toHaveBeenCalledWith(rows[0]);
  });

  it("Space also activates onRowClick", () => {
    const onRowClick = vi.fn();
    render(<DataConsole columns={columns} rows={rows} rowKey={(r) => r.id} onRowClick={onRowClick} />);
    const row = screen.getByText("Row Two").closest("tr")!;
    fireEvent.keyDown(row, { key: " " });
    expect(onRowClick).toHaveBeenCalledWith(rows[1]);
  });

  it("rows without onRowClick are not tabbable (no false affordance)", () => {
    render(<DataConsole columns={columns} rows={rows} rowKey={(r) => r.id} />);
    const row = screen.getByText("Row One").closest("tr")!;
    expect(row).not.toHaveAttribute("tabindex");
  });

  it("selected row exposes aria-selected", () => {
    render(
      <DataConsole
        columns={columns}
        rows={rows}
        rowKey={(r) => r.id}
        onRowClick={vi.fn()}
        selectedKey="r1"
      />
    );
    expect(screen.getByText("Row One").closest("tr")).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("Row Two").closest("tr")).toHaveAttribute("aria-selected", "false");
  });

  it("empty rows render the accessible EmptyRow state, not a blank table", () => {
    render(<DataConsole columns={columns} rows={[]} rowKey={(r: Row) => r.id} emptyLabel="No rows found." />);
    expect(screen.getByRole("status")).toHaveTextContent("No rows found.");
  });
});

describe("FormField", () => {
  it("generates a stable id and associates a real <label for>", () => {
    render(
      <FormField label="Target endpoint">
        <input value="" onChange={() => {}} />
      </FormField>
    );
    const input = screen.getByLabelText("Target endpoint");
    expect(input.tagName).toBe("INPUT");
  });

  it("preserves a caller-supplied id instead of overwriting it", () => {
    render(
      <FormField label="Target endpoint">
        <input id="custom-id" value="" onChange={() => {}} />
      </FormField>
    );
    expect(screen.getByLabelText("Target endpoint")).toHaveAttribute("id", "custom-id");
  });

  it("marks required fields with aria-required and a text (non-color-only) indicator", () => {
    render(
      <FormField label="Name" required>
        <input value="" onChange={() => {}} />
      </FormField>
    );
    const input = screen.getByLabelText(/Name/);
    expect(input).toHaveAttribute("aria-required", "true");
    expect(input).toHaveAttribute("required");
    expect(screen.getByText("(required)")).toBeInTheDocument();
  });

  it("links an error message via aria-describedby and exposes aria-invalid", () => {
    render(
      <FormField label="Endpoint" error="Endpoint URL is required.">
        <input value="" onChange={() => {}} />
      </FormField>
    );
    const input = screen.getByLabelText("Endpoint");
    expect(input).toHaveAttribute("aria-invalid", "true");
    const describedBy = input.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    const errorEl = document.getElementById(describedBy!.split(" ")[0]);
    expect(errorEl).toHaveTextContent("Endpoint URL is required.");
    expect(errorEl).toHaveAttribute("role", "alert");
  });

  it("links a hint via aria-describedby when there is no error", () => {
    render(
      <FormField label="Purpose" hint="Audit-logged with every resolve.">
        <input value="" onChange={() => {}} />
      </FormField>
    );
    const input = screen.getByLabelText("Purpose");
    const describedBy = input.getAttribute("aria-describedby");
    expect(describedBy).toBeTruthy();
    expect(document.getElementById(describedBy!)).toHaveTextContent("Audit-logged with every resolve.");
  });
});

describe("FormModal", () => {
  function Harness() {
    const [open, setOpen] = useState(false);
    return (
      <>
        <button onClick={() => setOpen(true)}>Open form</button>
        {open && (
          <FormModal title="New Thing" onClose={() => setOpen(false)}>
            <input placeholder="first field" />
            <button type="button">Save</button>
          </FormModal>
        )}
      </>
    );
  }

  it("renders as a labelled dialog and moves focus inside on open", () => {
    render(<Harness />);
    fireEvent.click(screen.getByText("Open form"));
    const dialog = screen.getByRole("dialog", { name: "New Thing" });
    expect(dialog).toBeInTheDocument();
    expect(dialog.contains(document.activeElement)).toBe(true);
  });

  it("closes on Escape and returns focus to the trigger", () => {
    render(<Harness />);
    const trigger = screen.getByText("Open form");
    trigger.focus();
    fireEvent.click(trigger);
    expect(screen.getByRole("dialog", { name: "New Thing" })).toBeInTheDocument();

    fireEvent.keyDown(document, { key: "Escape" });

    expect(screen.queryByRole("dialog", { name: "New Thing" })).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("closes on backdrop click", () => {
    const onClose = vi.fn();
    render(
      <FormModal title="New Thing" onClose={onClose}>
        <input placeholder="field" />
      </FormModal>
    );
    fireEvent.click(screen.getByRole("dialog").parentElement!);
    expect(onClose).toHaveBeenCalled();
  });

  it("does not close when clicking inside the dialog content", () => {
    const onClose = vi.fn();
    render(
      <FormModal title="New Thing" onClose={onClose}>
        <input placeholder="field" />
      </FormModal>
    );
    fireEvent.click(screen.getByRole("dialog"));
    expect(onClose).not.toHaveBeenCalled();
  });
});
