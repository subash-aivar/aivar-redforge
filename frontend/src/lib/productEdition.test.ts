import { describe, it, expect, afterEach } from "vitest";
import { getProductEdition } from "@/lib/productEdition";

const ORIGINAL = process.env.NEXT_PUBLIC_PRODUCT_EDITION;

afterEach(() => {
  if (ORIGINAL === undefined) {
    delete process.env.NEXT_PUBLIC_PRODUCT_EDITION;
  } else {
    process.env.NEXT_PUBLIC_PRODUCT_EDITION = ORIGINAL;
  }
});

describe("getProductEdition", () => {
  it("defaults to full when unset", () => {
    delete process.env.NEXT_PUBLIC_PRODUCT_EDITION;
    expect(getProductEdition()).toBe("full");
  });

  it("returns network_defense when explicitly set", () => {
    process.env.NEXT_PUBLIC_PRODUCT_EDITION = "network_defense";
    expect(getProductEdition()).toBe("network_defense");
  });

  it("returns full when explicitly set to full", () => {
    process.env.NEXT_PUBLIC_PRODUCT_EDITION = "full";
    expect(getProductEdition()).toBe("full");
  });

  it("fails safe to full (the superset) on an unrecognized value, never to a smaller surface", () => {
    process.env.NEXT_PUBLIC_PRODUCT_EDITION = "not_a_real_edition";
    expect(getProductEdition()).toBe("full");
  });
});
