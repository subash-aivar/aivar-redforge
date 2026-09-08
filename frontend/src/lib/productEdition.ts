/**
 * Frontend product_edition source of truth (ADR-0009). The ONE place
 * `NEXT_PUBLIC_PRODUCT_EDITION` is read — every consumer (nav filtering
 * today; a future shell/branding difference if ever needed) imports
 * `getProductEdition()` from here rather than reading `process.env`
 * directly, so there is exactly one place this could ever go wrong.
 *
 * Mirrors the backend's `redforge.core.config.Settings.product_edition`
 * default and fail-safe behavior: an unrecognized build-time value
 * falls back to "full" (the safe default) rather than crashing the
 * whole app at render time — unlike the backend, a bad frontend build
 * env var can't be "rejected at startup" in the same way, so failing
 * safe to the superset edition is the correct frontend-side behavior
 * (never fail safe to the *smaller* surface, which could silently hide
 * capability from a Full RedForge deployment).
 */
import type { ProductEdition } from "@/components/navigation/navConfig";

const VALID_EDITIONS: readonly ProductEdition[] = ["full", "network_defense"];

export function getProductEdition(): ProductEdition {
  const raw = process.env.NEXT_PUBLIC_PRODUCT_EDITION;
  if ((VALID_EDITIONS as readonly string[]).includes(raw ?? "")) {
    return raw as ProductEdition;
  }
  return "full";
}
