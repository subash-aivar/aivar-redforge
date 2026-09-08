"use client";

/**
 * Global Live Event Bus (Phase 4).
 *
 * Repository audit before writing this file confirmed exactly one real
 * SSE producer exists anywhere in the backend:
 * `GET /api/v1/security-operations/events/stream` (security_operations
 * bounded context). `useSecurityOperationsStream` is, and remains, the
 * only stream client. The problem this file fixes: that hook opens a
 * brand-new `fetch()` streaming connection per component that calls it.
 * Before this provider, `NotificationCenter` was the sole caller — one
 * connection. Adding a second live consumer (the Global Status Bar)
 * without this provider would have opened a second independent
 * connection to the same endpoint per browser tab, which is exactly the
 * "competing streaming mechanism" duplication the platform mandate
 * forbids — even though both would still be hitting the same real
 * endpoint. This provider calls the hook exactly once and every
 * consumer reads the shared result via context.
 */
import { createContext, useContext } from "react";
import {
  useSecurityOperationsStream,
  type SecurityOperationsStreamResult,
} from "@/lib/useSecurityOperationsStream";

const EventBusContext = createContext<SecurityOperationsStreamResult | null>(null);

export function EventBusProvider({ children }: { children: React.ReactNode }) {
  const stream = useSecurityOperationsStream(true);
  return <EventBusContext.Provider value={stream}>{children}</EventBusContext.Provider>;
}

/** Read the single shared platform event stream. Must be used within `EventBusProvider`. */
export function usePlatformEventBus(): SecurityOperationsStreamResult {
  const ctx = useContext(EventBusContext);
  if (!ctx) {
    throw new Error("usePlatformEventBus must be used within an EventBusProvider");
  }
  return ctx;
}
