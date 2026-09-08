import { describe, expect, it, afterEach } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { Breadcrumb } from "@/components/navigation/Breadcrumb";

afterEach(cleanup);

describe("Breadcrumb", () => {
  it("resolves the group and item label from the real nav config for a known route", () => {
    render(<Breadcrumb pathname="/findings" />);
    expect(screen.getByText("Command Center")).toBeInTheDocument();
    expect(screen.getByText("Findings")).toBeInTheDocument();
  });

  it("resolves nested routes via startsWith matching", () => {
    render(<Breadcrumb pathname="/compliance/frameworks" />);
    expect(screen.getByText("Investigation")).toBeInTheDocument();
    expect(screen.getByText("Compliance")).toBeInTheDocument();
  });

  it("renders nothing for a route with no nav entry, instead of a broken breadcrumb", () => {
    const { container } = render(<Breadcrumb pathname="/some-unmapped-route" />);
    expect(container).toBeEmptyDOMElement();
  });
});
