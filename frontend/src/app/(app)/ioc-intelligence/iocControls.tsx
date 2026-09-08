"use client";

/**
 * IOC Intelligence-only enterprise UX controls (M51.2 Phase A6.1).
 *
 * Scoped deliberately to this one feature — not added to the shared
 * `src/components/cc.tsx` primitive library, which 28+ other certified
 * pages already depend on. Everything here is pure presentation: no
 * validation rule, transition legality, or provider vocabulary is
 * invented here that the certified backend doesn't already enforce —
 * the closed provider list comes from `IOC_PROVIDER_VALUES`, itself a
 * mirror of the backend's real `ProviderName` enum.
 */
import { useEffect, useId, useMemo, useRef, useState } from "react";
import {
  IOC_CONFIDENCE_LABELS,
  IOC_CONFIDENCE_VALUES,
  IOC_PROVIDER_LABELS,
  IOC_PROVIDER_VALUES,
} from "@/lib/iocIntelligence";

// ── Shared dark input styling (matches the platform's established
// `border-gray-700 bg-gray-950 text-gray-200` convention — see
// threat-hunt/page.tsx's reject-reason textarea) ──────────────────────

export const DARK_INPUT_CLASS =
  "w-full rounded-md border border-gray-700 bg-gray-950 px-2.5 py-1.5 text-sm text-gray-200 placeholder:text-gray-600 transition-colors focus:border-red-600 focus:outline-none focus:ring-1 focus:ring-red-600/40 disabled:cursor-not-allowed disabled:opacity-50";

export const DARK_SELECT_CLASS = DARK_INPUT_CLASS + " appearance-none";

// ── Button ───────────────────────────────────────────────────────────

export function Button({
  variant = "secondary",
  loading,
  loadingLabel,
  children,
  className = "",
  ...rest
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger" | "ghost";
  loading?: boolean;
  loadingLabel?: string;
}) {
  const base =
    "inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-semibold transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-red-600/50 disabled:cursor-not-allowed disabled:opacity-50";
  const variantClass =
    variant === "primary"
      ? "border-red-800 bg-red-950/40 text-red-300 hover:bg-red-950/70 hover:border-red-700"
      : variant === "danger"
        ? "border-red-900 bg-transparent text-red-400 hover:bg-red-950/40 hover:border-red-700"
        : variant === "ghost"
          ? "border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-800"
          : "border-gray-700 bg-gray-900/60 text-gray-300 hover:bg-gray-800/70 hover:text-gray-100";
  return (
    <button
      type="button"
      className={`${base} ${variantClass} ${className}`}
      disabled={loading || rest.disabled}
      {...rest}
    >
      {loading && (
        <svg className="h-3 w-3 animate-spin text-current" viewBox="0 0 24 24" fill="none" aria-hidden="true">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4z" />
        </svg>
      )}
      {loading ? (loadingLabel ?? "Working…") : children}
    </button>
  );
}

// ── Collapsible section (drawer grouping) ───────────────────────────

export function CollapsibleSection({
  title,
  defaultOpen = true,
  children,
}: {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  return (
    <details open={defaultOpen} className="group rounded-lg border border-gray-800 bg-gray-900/40">
      <summary className="flex cursor-pointer list-none items-center justify-between px-3 py-2 text-[11px] font-semibold uppercase tracking-wider text-gray-400 hover:text-gray-200">
        {title}
        <span className="text-gray-600 transition-transform group-open:rotate-90">›</span>
      </summary>
      <div className="space-y-3 border-t border-gray-900 px-3 py-3">{children}</div>
    </details>
  );
}

// ── Confidence stepper (closed 4-value enum — segmented control) ────

export function ConfidenceStepper({
  value,
  onChange,
  label = "Confidence",
}: {
  value: string;
  onChange: (v: string) => void;
  label?: string;
}) {
  const idx = IOC_CONFIDENCE_VALUES.indexOf(value as (typeof IOC_CONFIDENCE_VALUES)[number]);
  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <label className="block text-xs font-medium text-gray-400">{label}</label>
        <span className="text-[10px] text-gray-600">
          {idx + 1} of {IOC_CONFIDENCE_VALUES.length}
        </span>
      </div>
      <div className="grid grid-cols-4 gap-1" role="radiogroup" aria-label={label}>
        {IOC_CONFIDENCE_VALUES.map((v) => (
          <button
            key={v}
            type="button"
            role="radio"
            aria-checked={value === v}
            onClick={() => onChange(v)}
            className={`rounded-md border px-2 py-1.5 text-[11px] font-semibold transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-red-600/50 ${
              value === v
                ? "border-red-700 bg-red-950/50 text-red-300"
                : "border-gray-800 bg-gray-950/60 text-gray-400 hover:border-gray-600 hover:text-gray-200"
            }`}
          >
            {IOC_CONFIDENCE_LABELS[v] ?? v}
          </button>
        ))}
      </div>
    </div>
  );
}

// ── Weight slider (0.01–1.0, matches backend's `gt=0.0, le=1.0`) ────

export function WeightSlider({
  value,
  onChange,
  label = "Weight",
}: {
  value: number;
  onChange: (v: number) => void;
  label?: string;
}) {
  const id = useId();
  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <label htmlFor={id} className="block text-xs font-medium text-gray-400">
          {label}
        </label>
        <span className="tabular-nums text-xs font-semibold text-gray-200">{value.toFixed(2)}</span>
      </div>
      <input
        id={id}
        type="range"
        min={0.01}
        max={1}
        step={0.01}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
        className="w-full accent-red-600"
      />
      <div className="mt-0.5 flex justify-between text-[10px] text-gray-600">
        <span>0.0</span>
        <span>1.0</span>
      </div>
    </div>
  );
}

// ── Datetime field (local-time picker, converts to/from ISO 8601) ──

export function DateTimeField({
  isoValue,
  onChange,
  label = "Observed At",
  required,
}: {
  isoValue: string;
  onChange: (iso: string) => void;
  label?: string;
  required?: boolean;
}) {
  const id = useId();
  const localValue = useMemo(() => {
    const d = new Date(isoValue);
    if (Number.isNaN(d.getTime())) return "";
    const pad = (n: number) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  }, [isoValue]);

  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-xs font-medium text-gray-400">
        {label}
        {required && (
          <span aria-hidden="true" className="ml-0.5 text-red-500">
            *
          </span>
        )}
      </label>
      <input
        id={id}
        type="datetime-local"
        value={localValue}
        required={required}
        onChange={(e) => {
          const v = e.target.value;
          if (!v) return;
          const parsed = new Date(v);
          if (!Number.isNaN(parsed.getTime())) onChange(parsed.toISOString());
        }}
        className={DARK_INPUT_CLASS}
      />
    </div>
  );
}

// ── Searchable provider select (closed vocabulary combobox) ────────

/**
 * Accessible combobox restricted to the closed provider vocabulary —
 * typing filters the list, but the committed value is always one of
 * `IOC_PROVIDER_VALUES`; free text can never be submitted (mission
 * requirement: "Do NOT allow arbitrary free text if backend only
 * supports approved providers").
 */
export function ProviderSearchSelect({
  value,
  onChange,
  label = "Source System (provider)",
  required,
}: {
  value: string;
  onChange: (v: string) => void;
  label?: string;
  required?: boolean;
}) {
  const id = useId();
  const listId = `${id}-listbox`;
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState(IOC_PROVIDER_LABELS[value] ?? value);
  const [activeIdx, setActiveIdx] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setQuery(IOC_PROVIDER_LABELS[value] ?? value);
  }, [value]);

  useEffect(() => {
    function onDocClick(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
        setQuery(IOC_PROVIDER_LABELS[value] ?? value);
      }
    }
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, [value]);

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle || needle === (IOC_PROVIDER_LABELS[value] ?? value).toLowerCase()) {
      return IOC_PROVIDER_VALUES;
    }
    return IOC_PROVIDER_VALUES.filter(
      (p) => p.toLowerCase().includes(needle) || (IOC_PROVIDER_LABELS[p] ?? "").toLowerCase().includes(needle)
    );
  }, [query, value]);

  function commit(v: string) {
    onChange(v);
    setQuery(IOC_PROVIDER_LABELS[v] ?? v);
    setOpen(false);
  }

  return (
    <div ref={containerRef} className="relative">
      <label htmlFor={id} className="mb-1 block text-xs font-medium text-gray-400">
        {label}
        {required && (
          <span aria-hidden="true" className="ml-0.5 text-red-500">
            *
          </span>
        )}
      </label>
      <input
        id={id}
        type="text"
        role="combobox"
        aria-expanded={open}
        aria-controls={listId}
        aria-autocomplete="list"
        autoComplete="off"
        required={required}
        value={query}
        onFocus={() => setOpen(true)}
        onChange={(e) => {
          setQuery(e.target.value);
          setOpen(true);
          setActiveIdx(0);
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setOpen(true);
            setActiveIdx((i) => Math.min(i + 1, filtered.length - 1));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setActiveIdx((i) => Math.max(i - 1, 0));
          } else if (e.key === "Enter") {
            e.preventDefault();
            if (filtered[activeIdx]) commit(filtered[activeIdx]);
          } else if (e.key === "Escape") {
            if (!open) return;
            // Only swallow Escape while the listbox itself is open — a
            // second Escape (listbox already closed) must fall through
            // to the enclosing FormModal's own Escape-to-close handler,
            // not be silently eaten here.
            // FormModal's Escape-to-close listener is a separate,
            // independent `document.addEventListener("keydown", ...)`
            // call. In this app's React root, React's own delegated
            // dispatch listener is *also* attached at `document` — so
            // React's handler here and FormModal's handler are two
            // sibling listeners on the exact same target.
            // `stopPropagation()` only stops an event moving to the
            // *next* node in the DOM path; it does nothing to a second
            // listener already registered on the *same* node. Only
            // `stopImmediatePropagation()` prevents that sibling
            // listener from firing too.
            e.nativeEvent.stopImmediatePropagation();
            setOpen(false);
            setQuery(IOC_PROVIDER_LABELS[value] ?? value);
          }
        }}
        placeholder="Search providers…"
        className={DARK_INPUT_CLASS}
      />
      {open && (
        <ul
          id={listId}
          role="listbox"
          aria-label={label}
          className="absolute z-10 mt-1 max-h-48 w-full overflow-y-auto rounded-md border border-gray-700 bg-gray-950 py-1 shadow-xl"
        >
          {filtered.length === 0 ? (
            <li className="px-2.5 py-1.5 text-xs text-gray-600">No matching provider.</li>
          ) : (
            filtered.map((p, i) => (
              <li key={p} role="presentation">
                <button
                  type="button"
                  role="option"
                  aria-selected={p === value}
                  onMouseDown={(e) => e.preventDefault()}
                  onClick={() => commit(p)}
                  className={`block w-full px-2.5 py-1.5 text-left text-xs ${
                    i === activeIdx ? "bg-gray-800 text-gray-100" : "text-gray-300"
                  } ${p === value ? "font-semibold text-red-300" : ""}`}
                >
                  {IOC_PROVIDER_LABELS[p] ?? p}
                  <span className="ml-1.5 text-[10px] text-gray-600">{p}</span>
                </button>
              </li>
            ))
          )}
        </ul>
      )}
    </div>
  );
}

// ── Friendly, honest error rendering for provider-vocabulary errors ─

/**
 * The backend's `Unrecognized source_system '...'` error is real
 * domain validation, not a bug (see Phase A6 verification). This only
 * reformats that exact, already-real backend message with the same
 * closed provider list the select control already offers — it never
 * invents a vocabulary the backend doesn't enforce.
 */
export function ApiErrorPanel({ message }: { message: string }) {
  const isProviderError = /source_system|provider/i.test(message) && /unrecognized|unsupported/i.test(message);
  return (
    <div role="alert" className="rounded-md border border-red-900 bg-red-950/40 px-3 py-2 text-xs text-red-300">
      <p className="font-semibold">{isProviderError ? "Unsupported Provider" : "Request Failed"}</p>
      <p className="mt-0.5 text-red-300/90">{message}</p>
      {isProviderError && (
        <div className="mt-2">
          <p className="text-[10px] font-semibold uppercase tracking-wider text-red-400/80">Allowed Providers</p>
          <ul className="mt-1 grid grid-cols-2 gap-x-3 gap-y-0.5 text-[11px] text-red-200/90">
            {IOC_PROVIDER_VALUES.map((p) => (
              <li key={p}>• {IOC_PROVIDER_LABELS[p] ?? p}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
