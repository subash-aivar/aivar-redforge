/**
 * Maps a real `entity_type` emitted by the security_operations event
 * stream to a real detail route this frontend already has — never a
 * guessed or fabricated URL. Verified by grep against the backend's
 * actual `entity_type="..."` publish sites, matched against frontend
 * routes that actually exist. Shared by every consumer of the live
 * event bus that offers drill-down (`NotificationCenter`, the SOC
 * Operations page) so the mapping is defined exactly once.
 *
 * `entity_type` values with no real per-entity detail page yet
 * (`runtime_component`, `network_validation_run`,
 * `continuous_validation_policy`, `threat_intel_enrichment`)
 * intentionally return `null` rather than a link that 404s.
 */
export function entityLink(entityType: string, entityId: string): string | null {
  switch (entityType) {
    case "investigation_case":
      return `/investigations/${entityId}`;
    case "validation_execution":
      return `/security-operations/executions/${entityId}`;
    case "ddos_incident":
      return `/ddos/incidents/${entityId}`;
    case "behavior_detection":
      return `/behavior/detections/${entityId}`;
    default:
      return null;
  }
}
