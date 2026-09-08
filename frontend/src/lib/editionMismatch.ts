/**
 * Frontend<->backend product_edition consistency check (ADR-0009).
 *
 * Packaging/config integrity, NOT RBAC: the backend alone decides which
 * routes are mounted (`Settings.product_edition`, see
 * `redforge.api.router.build_root_router`); nothing here grants or
 * widens API access. This only decides whether the frontend shell it
 * was built as ("full" or "network_defense", baked in at build time via
 * `NEXT_PUBLIC_PRODUCT_EDITION` — see `getProductEdition()`) matches the
 * edition the backend it is talking to actually reports
 * (`GET /api/v1/runtime/status` -> `product_edition`, see
 * `redforge.api.v1.runtime.runtime_status`). A mismatch means an
 * operator pointed a Full-built frontend at a Network Defense backend
 * (or vice versa) — a deployment/config error, not a security bypass:
 * the backend's own mounted route set is unaffected either way.
 */
import type { ProductEdition } from "@/components/navigation/navConfig";

export interface EditionMismatchInfo {
  mismatched: boolean;
  frontendEdition: ProductEdition;
  backendEdition: string;
}

/**
 * Pure comparison — takes the already-resolved frontend edition and the
 * `product_edition` field reported by `/api/v1/runtime/status`, and
 * returns whether they disagree. Kept as a pure function (no fetch, no
 * React) so it can be exercised without a running backend or a browser.
 */
export function detectEditionMismatch(
  frontendEdition: ProductEdition,
  backendEdition: string | undefined | null,
): EditionMismatchInfo {
  const backend = backendEdition ?? "";
  return {
    mismatched: backend !== "" && backend !== frontendEdition,
    frontendEdition,
    backendEdition: backend,
  };
}

/**
 * Structured diagnostic for the operator-facing error screen and logs.
 * Deliberately carries only the two edition strings — no env dump, no
 * tokens, no full settings/config object.
 */
export function editionMismatchDiagnostic(info: EditionMismatchInfo): string {
  return (
    `RedForge product_edition mismatch: frontend built as ` +
    `"${info.frontendEdition}" but backend reports ` +
    `"${info.backendEdition}". Rebuild the frontend for the backend's ` +
    `edition (or point it at a backend running the same edition) — see ` +
    `ADR-0009.`
  );
}
