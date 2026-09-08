/**
 * Frontend product_edition source of truth (ADR-0009). The ONE place
 * `NEXT_PUBLIC_PRODUCT_EDITION` is read — every consumer (nav filtering
 * today; a future shell/branding difference if ever needed) imports
 * `getProductEdition()` from here rather than reading `process.env`
 * directly, so there is exactly one place this could ever go wrong.
 *
 * Mirrors the backend's `redforge.core.config.Settings.product_edition`
 * fail-safety guarantee, not just its default: missing env is
 * backward-compatible ("full", matching the backend Pydantic field
 * default), an explicit "full"/"network_defense" is returned as-is,
 * and — like the backend's Pydantic `Literal` validation, which
 * refuses to construct `Settings` at all for an unrecognized value —
 * an unrecognized value here throws at module-evaluation time instead
 * of silently coercing to any edition. `NEXT_PUBLIC_*` values are
 * inlined into the bundle at build time, so this throw fires the
 * moment this module is first evaluated (import time), deterministically
 * failing `next build`/`next dev` in both the server and client bundles
 * this module is compiled into, the same way a bad backend env fails
 * `Settings()` construction before the app ever serves a request.
 * Previously this fell back to "full" on an unrecognized value — that
 * was a real gap: a misconfigured `NEXT_PUBLIC_PRODUCT_EDITION` (typo,
 * stale value) would silently ship the superset (Full) shell instead
 * of failing loudly, which is exactly the class of silent-misconfig
 * bug ADR-0009 exists to prevent on the backend side.
 *
 * The throw here is defense-in-depth for any direct caller/test, but
 * it is NOT what makes an invalid value fail `next build`/`next dev`
 * deterministically — verified that a "use client" page calling this
 * during static generation does not reliably reach this line at build
 * time. The build/dev-server-guaranteed enforcement point is
 * `next.config.ts`, which duplicates this same validation and runs on
 * every Next.js CLI invocation before any build work starts.
 */
import type { ProductEdition } from "@/components/navigation/navConfig";

const VALID_EDITIONS: readonly ProductEdition[] = ["full", "network_defense"];

function resolveProductEdition(): ProductEdition {
  const raw = process.env.NEXT_PUBLIC_PRODUCT_EDITION;
  if (raw === undefined || raw === "") {
    return "full";
  }
  if ((VALID_EDITIONS as readonly string[]).includes(raw)) {
    return raw as ProductEdition;
  }
  throw new Error(
    `Invalid NEXT_PUBLIC_PRODUCT_EDITION: "${raw}". Must be one of ` +
      `${VALID_EDITIONS.join(", ")}, or unset (defaults to "full"). ` +
      `This build cannot be trusted to expose the correct product ` +
      `surface, so it fails at build/start time rather than silently ` +
      `falling back to any edition.`,
  );
}

// Recomputed on every call (not memoized at module scope) so the
// throw fires deterministically the first time ANY consumer actually
// reads the edition — every real consumer (`AppLayout`,
// `security-operations/page.tsx`, `NavigationShell`'s default) calls
// this at module top-level render/mount time, so in practice this
// still fails before the app renders anything meaningful, without
// forcing a module-load-order dependency on `NEXT_PUBLIC_*` being set
// before this file is first imported (which would make the throw's
// timing depend on import order rather than on the value itself) and
// without breaking unit tests that mutate `process.env` per-test.
export function getProductEdition(): ProductEdition {
  return resolveProductEdition();
}
