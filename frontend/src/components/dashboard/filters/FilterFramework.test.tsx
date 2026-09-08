import { describe, expect, it, vi, afterEach } from "vitest";
import { cleanup, render, screen, fireEvent } from "@testing-library/react";
import { FilterFramework, type FilterDef } from "@/components/dashboard/filters/FilterFramework";

afterEach(cleanup);

const filters: FilterDef[] = [
  {
    id: "severity",
    label: "Severity",
    options: [
      { value: "critical", label: "Critical" },
      { value: "high", label: "High" },
    ],
  },
];

describe("FilterFramework", () => {
  it("calls onChange with the selected value", () => {
    const onChange = vi.fn();
    render(<FilterFramework filters={filters} state={{}} onChange={onChange} />);
    fireEvent.change(screen.getByDisplayValue("Severity: All"), { target: { value: "critical" } });
    expect(onChange).toHaveBeenCalledWith("severity", "critical");
  });

  it("shows a Clear button only when a filter is active", () => {
    const { rerender } = render(
      <FilterFramework filters={filters} state={{}} onChange={vi.fn()} onClear={vi.fn()} />
    );
    expect(screen.queryByText(/Clear/)).not.toBeInTheDocument();

    rerender(
      <FilterFramework
        filters={filters}
        state={{ severity: "critical" }}
        onChange={vi.fn()}
        onClear={vi.fn()}
      />
    );
    expect(screen.getByText("Clear (1)")).toBeInTheDocument();
  });
});
