"use client";

/**
 * IOC Intelligence console (M51.2 Phase A6, hardened in Phase A6.1).
 *
 * One operational page for the certified IOC backend: tenant + global
 * scope, provenance/evidence, lifecycle vs. epistemic state (never
 * conflated), and only the mutations the current user's real
 * permissions (`ioc_intel:*` for tenant, `platform:ioc_intel:*` for
 * global — fetched from the backend, never inferred from org role
 * names) actually allow. The backend remains authoritative for every
 * action; hiding a button here is UX only.
 *
 * Phase A6.1 is UX-only: no domain/application/infrastructure/API/DTO/
 * RBAC/validation change. Every enterprise control added here (the
 * searchable provider select, confidence stepper, weight slider) is a
 * presentation layer over the exact same closed vocabularies and the
 * exact same request shapes Phase A6 already certified.
 */
import { useEffect, useMemo, useState } from "react";
import {
  AsyncContent,
  DataConsole,
  FormField,
  FormModal,
  InvestigationDrawer,
  KpiTile,
  PageHeader,
  SearchInput,
  StatusPill,
  useAsync,
  type AsyncState,
  type ConsoleColumn,
  type DrawerField,
} from "@/components/cc";
import { ApiError } from "@/lib/api";
import { getMe } from "@/lib/auth";
import { getPlatformAccess } from "@/lib/platform";
import { getEffectiveAccess } from "@/lib/rbac";
import {
  IOC_EPISTEMIC_VALUES,
  IOC_LIFECYCLE_VALUES,
  IOC_PROVIDER_REFERENCE_PLACEHOLDER,
  IOC_TYPE_VALUES,
  IOC_VALIDITY_VALUES,
  addEvidenceCitation,
  addSourceAttribution,
  disputeIoc,
  getIoc,
  listGlobalIocs,
  listTenantIocs,
  observeGlobalIoc,
  observeTenantIoc,
  refreshIoc,
  refuteIoc,
  revokeIoc,
  supersedeIoc,
  transitionEpistemicState,
  transitionLifecycle,
  type EvidenceCitationInput,
  type IocDetail,
  type IocSortField,
  type IocSummary,
  type PaginatedIocList,
  type SourceAttributionInput,
} from "@/lib/iocIntelligence";
import {
  ApiErrorPanel,
  Button,
  CollapsibleSection,
  ConfidenceStepper,
  DARK_INPUT_CLASS,
  DARK_SELECT_CLASS,
  DateTimeField,
  ProviderSearchSelect,
  WeightSlider,
} from "./iocControls";

const PAGE_SIZE = 25;
const TENANT_READ = "ioc_intel:read";
const TENANT_OBSERVE = "ioc_intel:observe";
const TENANT_MANAGE = "ioc_intel:manage";
const PLATFORM_READ = "platform:ioc_intel:read";
const PLATFORM_MANAGE = "platform:ioc_intel:manage";

// Sortable fields are exactly the backend's whitelisted `IocSortField`
// set (`created_at`/`updated_at`/`valid_until`/`ioc_type`/`lifecycle`/
// `epistemic_state`) — no client-only sort key (indicator, source/
// evidence count) is offered, since those cannot be sorted across the
// full dataset server-side and a client-side-only sort here would
// silently only reorder the current page, contradicting the sort
// selector's own claim of sorting the result set.
type SortKey = IocSortField;

/** Only a real optimistic-lock conflict (a concurrent writer already
 * changed this record) gets the "reload and retry" message. A 409 is
 * also how the backend reports invalid lifecycle/epistemic transitions,
 * duplicate source attributions, and other domain-rule rejections
 * (`InvalidLifecycleTransitionError`, `InvalidEpistemicStateTransitionError`,
 * `DuplicateSourceAttributionError`, `IocIntelIntegrityError` all map to
 * 409 too, per `exception_handlers.py`) — those are real, specific,
 * already-understandable messages from the backend and must not be
 * overwritten with a generic "someone else changed this" claim that
 * would actively mislead the operator about what actually happened.
 */
function isOptimisticLockConflict(err: unknown): boolean {
  return err instanceof ApiError && err.status === 409 && err.message.includes("Optimistic lock conflict");
}

function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (isOptimisticLockConflict(err)) {
      return "This record was changed by someone else since you loaded it. " +
        "The latest version has been reloaded below — review it before retrying.";
    }
    return err.message;
  }
  if (err instanceof Error) return err.message;
  return "Something went wrong.";
}

export default function IocIntelligencePage() {
  const [scope, setScope] = useState<"tenant" | "global">("tenant");
  const [lifecycleFilter, setLifecycleFilter] = useState("");
  const [epistemicFilter, setEpistemicFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [validityFilter, setValidityFilter] = useState<"" | "valid" | "lapsed">("");
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [sortKey, setSortKey] = useState<SortKey>("updated_at");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  // Debounce free-text search so every keystroke doesn't fire a fresh
  // server-side query — the committed `search` value (not `searchInput`)
  // is what actually drives the fetch below.
  useEffect(() => {
    const handle = setTimeout(() => {
      setSearch(searchInput);
      setOffset(0);
    }, 300);
    return () => clearTimeout(handle);
  }, [searchInput]);

  function resetFilters() {
    setLifecycleFilter("");
    setEpistemicFilter("");
    setTypeFilter("");
    setValidityFilter("");
    setSearchInput("");
    setSearch("");
    setSortKey("updated_at");
    setSortDir("desc");
    setOffset(0);
  }

  const filtersActive =
    !!lifecycleFilter || !!epistemicFilter || !!typeFilter || !!validityFilter || !!search;

  const [perms, setPerms] = useState<Set<string> | null>(null);
  const [platformPerms, setPlatformPerms] = useState<Set<string> | null>(null);

  useEffect(() => {
    getMe()
      .then((me) => getEffectiveAccess(me.user_id))
      .then((ea) => setPerms(new Set(ea.effective_permissions)))
      .catch(() => setPerms(new Set()));
    getPlatformAccess()
      .then((access) => setPlatformPerms(new Set(access.permissions)))
      .catch(() => setPlatformPerms(new Set()));
  }, []);

  const canReadTenant = perms === null || perms.has(TENANT_READ);
  const canObserveTenant = !!perms?.has(TENANT_OBSERVE);
  const canManageTenant = !!perms?.has(TENANT_MANAGE);
  const canReadGlobal = !!platformPerms?.has(PLATFORM_READ);
  const canManageGlobal = !!platformPerms?.has(PLATFORM_MANAGE);

  const listState: AsyncState<PaginatedIocList> = useAsync(() => {
    const filters = {
      lifecycle: lifecycleFilter || undefined,
      epistemic_state: epistemicFilter || undefined,
      ioc_type: typeFilter || undefined,
      search: search.trim() || undefined,
      validity: validityFilter || undefined,
      sort_by: sortKey,
      sort_dir: sortDir,
      limit: PAGE_SIZE,
      offset,
    };
    return scope === "tenant" ? listTenantIocs(filters) : listGlobalIocs(filters);
  }, [
    scope,
    lifecycleFilter,
    epistemicFilter,
    typeFilter,
    search,
    validityFilter,
    sortKey,
    sortDir,
    offset,
  ]);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<IocDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [observeOpen, setObserveOpen] = useState<"tenant" | "global" | null>(null);

  function reloadDetail(id: string) {
    setDetailError(null);
    getIoc(id)
      .then(setDetail)
      .catch((err) => setDetailError(errorMessage(err)));
  }

  function openRow(row: IocSummary) {
    setSelectedId(row.ioc_id);
    setActionError(null);
    reloadDetail(row.ioc_id);
  }

  function closeDrawer() {
    setSelectedId(null);
    setDetail(null);
    setDetailError(null);
    setActionError(null);
  }

  // Every filter/search/sort is now a real server-side query parameter
  // (M51.2 Slice 2.1) — the page renders exactly the rows the backend
  // returns, with no client-side re-filtering or re-sorting of any
  // kind. `visibleItems` is just the current page's rows.
  const visibleItems = listState.data?.items ?? [];

  const kpis = useMemo(() => {
    const items = listState.data?.items ?? [];
    return {
      total: listState.data?.total ?? 0,
      active: items.filter((i) => i.lifecycle === "active").length,
      expired: items.filter((i) => i.lifecycle === "expired").length,
      disputedOrRefuted: items.filter(
        (i) => i.epistemic_state === "disputed" || i.epistemic_state === "refuted"
      ).length,
    };
  }, [listState.data]);

  const canMutate = scope === "tenant" ? canManageTenant : canManageGlobal;

  async function runMutation(fn: () => Promise<IocDetail>) {
    setActionError(null);
    try {
      const updated = await fn();
      setDetail(updated);
      listState.reload();
    } catch (err) {
      setActionError(errorMessage(err));
      // Only a genuine optimistic-lock conflict means our in-memory
      // `detail` is stale relative to the server's row_version — a
      // domain-rule rejection (also a 409) doesn't mean the record
      // changed underneath us, so it must not trigger a reload.
      if (isOptimisticLockConflict(err) && detail) {
        reloadDetail(detail.ioc_id);
      }
    }
  }

  function sortIndicator(key: SortKey) {
    if (sortKey !== key) return null;
    return <span className="ml-1 text-red-400">{sortDir === "asc" ? "▲" : "▼"}</span>;
  }

  const columns: ConsoleColumn<IocSummary>[] = [
    {
      key: "indicator",
      header: "Indicator",
      render: (r) => <code className="text-[11px]">{r.canonical_key}</code>,
    },
    {
      key: "type",
      header: (<>Type{sortIndicator("ioc_type")}</>) as unknown as string,
      render: (r) => r.ioc_type.toUpperCase(),
    },
    {
      key: "scope",
      header: "Scope",
      render: (r) => (
        <span
          className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
            r.tenant_id
              ? "border-sky-800 bg-sky-950/50 text-sky-300"
              : "border-purple-800 bg-purple-950/50 text-purple-300"
          }`}
        >
          {r.tenant_id ? "Tenant" : "Global"}
        </span>
      ),
    },
    {
      key: "lifecycle",
      header: (<>Lifecycle{sortIndicator("lifecycle")}</>) as unknown as string,
      render: (r) => <StatusPill status={r.lifecycle} />,
    },
    {
      key: "epistemic",
      header: (<>Epistemic State{sortIndicator("epistemic_state")}</>) as unknown as string,
      render: (r) => <StatusPill status={r.epistemic_state} />,
    },
    {
      key: "sources",
      header: "Source Count",
      render: (r) => r.source_count,
    },
    {
      key: "evidence",
      header: "Evidence Count",
      render: (r) => r.evidence_count,
    },
    {
      key: "validity",
      header: (<>Expires{sortIndicator("valid_until")}</>) as unknown as string,
      render: (r) => (r.valid_until ? new Date(r.valid_until).toLocaleString() : "No expiry"),
    },
    {
      key: "updated",
      header: (<>Last Updated{sortIndicator("updated_at")}</>) as unknown as string,
      render: (r) => new Date(r.updated_at).toLocaleString(),
    },
  ];

  const [showAddSource, setShowAddSource] = useState(false);
  const [showAddEvidence, setShowAddEvidence] = useState(false);

  async function handleRefute() {
    const reason = window.prompt("Reason for refuting this IOC (required):");
    if (!reason) return;
    await runMutation(() => refuteIoc(detail!.ioc_id, reason));
  }

  async function handleSupersede() {
    if (
      !window.confirm(
        "Supersede this IOC? It will be marked superseded — this cannot be undone from this screen."
      )
    ) {
      return;
    }
    await runMutation(() => supersedeIoc(detail!.ioc_id));
  }

  async function handleRevoke() {
    if (
      !window.confirm(
        "Revoke this IOC? Revocation is a terminal state — this cannot be undone from this screen."
      )
    ) {
      return;
    }
    await runMutation(() => revokeIoc(detail!.ioc_id));
  }

  const actionsField: DrawerField | null =
    detail && canMutate
      ? {
          label: "Authorized Actions",
          value: (
            <div className="space-y-2">
              {actionError && <ApiErrorPanel message={actionError} />}
              <div className="flex flex-wrap gap-1.5">
                <Button variant="secondary" onClick={() => setShowAddSource(true)}>
                  Add Source
                </Button>
                <Button variant="secondary" onClick={() => setShowAddEvidence(true)}>
                  Add Evidence
                </Button>
                <Button variant="secondary" onClick={() => runMutation(() => refreshIoc(detail.ioc_id))}>
                  Refresh
                </Button>
                <Button variant="secondary" onClick={handleSupersede}>
                  Supersede
                </Button>
                <Button variant="secondary" onClick={() => runMutation(() => transitionLifecycle(detail.ioc_id, "expired"))}>
                  Mark Expired
                </Button>
                <Button variant="danger" onClick={handleRevoke}>
                  Revoke
                </Button>
                <Button variant="secondary" onClick={() => runMutation(() => transitionEpistemicState(detail.ioc_id, "evidence"))}>
                  Advance to Evidence
                </Button>
                <Button
                  variant="secondary"
                  className="border-amber-800 text-amber-300 hover:border-amber-600"
                  onClick={() => runMutation(() => disputeIoc(detail.ioc_id))}
                >
                  Dispute
                </Button>
                <Button variant="danger" onClick={handleRefute}>
                  Refute
                </Button>
              </div>
              <p className="text-[10px] text-gray-600">
                Only transitions valid for this record&apos;s current state will succeed —
                the backend validates every transition; an invalid one surfaces its own
                error here.
              </p>
            </div>
          ),
        }
      : null;

  const drawerFields: DrawerField[] = detail
    ? [
        ...(actionsField ? [actionsField] : []),
        {
          label: "General",
          value: (
            <CollapsibleSection title="General" defaultOpen>
              <DetailRow label="IOC ID" value={<code className="text-[11px]">{detail.ioc_id}</code>} />
              <DetailRow label="Canonical Identity" value={<code className="text-[11px]">{detail.canonical_key}</code>} />
              <DetailRow label="Indicator Type" value={detail.ioc_type.toUpperCase()} />
              <DetailRow
                label="Scope"
                value={detail.tenant_id ? `Tenant (${detail.tenant_id})` : "Global (platform-shared)"}
              />
              <DetailRow label="Created" value={new Date(detail.created_at).toLocaleString()} />
              <DetailRow label="Last Updated" value={new Date(detail.updated_at).toLocaleString()} />
            </CollapsibleSection>
          ),
        },
        {
          label: "Lifecycle & Epistemic Trust",
          value: (
            <CollapsibleSection title="Lifecycle & Epistemic Trust" defaultOpen>
              <DetailRow label="Lifecycle (operational relevance)" value={<StatusPill status={detail.lifecycle} />} />
              <DetailRow label="Epistemic State (trust)" value={<StatusPill status={detail.epistemic_state} />} />
              <DetailRow label="Valid From" value={new Date(detail.valid_from).toLocaleString()} />
              <DetailRow
                label="Expires"
                value={detail.valid_until ? new Date(detail.valid_until).toLocaleString() : "No expiry set"}
              />
            </CollapsibleSection>
          ),
        },
        {
          label: "Sources",
          value: (
            <CollapsibleSection title={`Source Attributions (${detail.source_attributions.length})`} defaultOpen>
              {detail.source_attributions.length === 0 ? (
                <p className="text-xs text-gray-500">No source attribution recorded yet.</p>
              ) : (
                <ul className="space-y-1">
                  {detail.source_attributions.map((a, i) => (
                    <li key={i} className="rounded border border-gray-800 px-2 py-1 text-xs">
                      <span className="font-semibold">{a.source_system}</span>
                      {" · ref "}
                      <code>{a.external_id}</code>
                      {" · confidence "}
                      {a.confidence}
                      {" · observed "}
                      {new Date(a.observed_at).toLocaleString()}
                    </li>
                  ))}
                </ul>
              )}
            </CollapsibleSection>
          ),
        },
        {
          label: "Evidence",
          value: (
            <CollapsibleSection title={`Evidence Citations (${detail.evidence_citations.length})`} defaultOpen>
              {detail.evidence_citations.length === 0 ? (
                <p className="text-xs text-gray-500">No tenant evidence citation recorded yet.</p>
              ) : (
                <ul className="space-y-1">
                  {detail.evidence_citations.map((c, i) => (
                    <li key={i} className="rounded border border-gray-800 px-2 py-1 text-xs">
                      <code>{c.value}</code>
                    </li>
                  ))}
                </ul>
              )}
            </CollapsibleSection>
          ),
        },
        {
          label: "History",
          value: (
            <CollapsibleSection title="History" defaultOpen={false}>
              <p className="text-xs text-gray-500">
                Change history is not exposed by the certified IOC API yet. Source and
                lifecycle/epistemic-state changes above reflect the current state only.
              </p>
            </CollapsibleSection>
          ),
        },
      ]
    : [];

  return (
    <div>
      <PageHeader
        title="IOC Intelligence"
        subtitle="Canonical observable-indicator identity, provenance, lifecycle, and epistemic trust — tenant and platform-global scope."
      />
      {/* Deliberately rendered as its own row rather than through
          PageHeader's `actions` slot: that slot wraps its content in a
          `shrink-0` flex item, which — because a `flex-shrink: 0` node's
          intrinsic width is computed as if unwrapped — never gives its
          own inner `flex-wrap` a narrower width to wrap against, so on
          narrow viewports the three buttons below overflowed instead of
          wrapping (verified via getBoundingClientRect at 375px: a
          381px-wide row inside a 327px header). PageHeader is a shared
          primitive 28+ other certified pages depend on, so this works
          around it locally rather than changing its shared behavior. */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Button variant={scope === "tenant" ? "primary" : "secondary"} onClick={() => setScope("tenant")}>
          Tenant Scope
        </Button>
        <Button variant={scope === "global" ? "primary" : "secondary"} onClick={() => setScope("global")}>
          Global Scope
        </Button>
        {scope === "tenant" && canObserveTenant && (
          <Button variant="primary" onClick={() => setObserveOpen("tenant")}>
            + Observe Tenant IOC
          </Button>
        )}
        {scope === "global" && canManageGlobal && (
          <Button variant="primary" onClick={() => setObserveOpen("global")}>
            + Observe Global IOC
          </Button>
        )}
      </div>

      {scope === "global" && !canReadGlobal && platformPerms !== null ? (
        <div role="alert" className="mb-4 rounded-lg border border-gray-800 bg-gray-900/60 px-4 py-6 text-center text-sm text-gray-400">
          You don&apos;t have platform authority to view global IOC intelligence. Ask a
          platform administrator to grant it.
        </div>
      ) : scope === "tenant" && !canReadTenant ? (
        <div role="alert" className="mb-4 rounded-lg border border-gray-800 bg-gray-900/60 px-4 py-6 text-center text-sm text-gray-400">
          You don&apos;t have permission to view tenant IOC intelligence. Ask an
          organization administrator to grant it.
        </div>
      ) : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
            <KpiTile label="Total Matching Results" value={kpis.total} hint="Entire filtered dataset" />
            <KpiTile label="Active (this page)" value={kpis.active} tone="ok" />
            <KpiTile label="Expired (this page)" value={kpis.expired} tone="warning" />
            <KpiTile
              label="Disputed / Refuted (this page)"
              value={kpis.disputedOrRefuted}
              tone={kpis.disputedOrRefuted > 0 ? "danger" : "default"}
            />
          </div>

          <div className="mb-4 flex flex-wrap items-end gap-3 rounded-lg border border-gray-800 bg-gray-900/30 p-3">
            <div className="min-w-[180px] flex-1">
              <label className="mb-1 block text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                Search
              </label>
              <SearchInput
                value={searchInput}
                onChange={setSearchInput}
                placeholder="Search the entire dataset by indicator value…"
              />
            </div>
            <FilterSelect
              label="Type"
              value={typeFilter}
              onChange={(v) => {
                setTypeFilter(v);
                setOffset(0);
              }}
              options={[{ value: "", label: "All types" }, ...IOC_TYPE_VALUES.map((v) => ({ value: v, label: v.toUpperCase() }))]}
            />
            <FilterSelect
              label="Lifecycle"
              value={lifecycleFilter}
              onChange={(v) => {
                setLifecycleFilter(v);
                setOffset(0);
              }}
              options={[{ value: "", label: "All lifecycles" }, ...IOC_LIFECYCLE_VALUES.map((v) => ({ value: v, label: v }))]}
            />
            <FilterSelect
              label="Epistemic"
              value={epistemicFilter}
              onChange={(v) => {
                setEpistemicFilter(v);
                setOffset(0);
              }}
              options={[{ value: "", label: "All epistemic states" }, ...IOC_EPISTEMIC_VALUES.map((v) => ({ value: v, label: v }))]}
            />
            <FilterSelect
              label="Validity"
              value={validityFilter}
              onChange={(v) => {
                setValidityFilter(v as typeof validityFilter);
                setOffset(0);
              }}
              options={[
                { value: "", label: "Any validity" },
                ...IOC_VALIDITY_VALUES.map((v) => ({
                  value: v,
                  label: v === "valid" ? "Valid now" : "Lapsed (past valid_until)",
                })),
              ]}
            />
            <FilterSelect
              label="Sort by"
              value={sortKey}
              onChange={(v) => {
                setSortKey(v as SortKey);
                setOffset(0);
              }}
              options={[
                { value: "updated_at", label: "Last Updated" },
                { value: "created_at", label: "First Observed" },
                { value: "ioc_type", label: "Type" },
                { value: "lifecycle", label: "Lifecycle" },
                { value: "epistemic_state", label: "Epistemic State" },
                { value: "valid_until", label: "Expires" },
              ]}
            />
            <Button
              variant="secondary"
              aria-label={`Sort direction: ${sortDir === "asc" ? "ascending" : "descending"}`}
              onClick={() => setSortDir((d) => (d === "asc" ? "desc" : "asc"))}
            >
              {sortDir === "asc" ? "▲ Asc" : "▼ Desc"}
            </Button>
            {filtersActive && (
              <Button variant="secondary" onClick={resetFilters}>
                Reset filters
              </Button>
            )}
            <div className="ml-auto flex items-center gap-2 text-xs text-gray-500">
              <Button variant="secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
                Prev
              </Button>
              <span>
                {kpis.total > 0
                  ? `${offset + 1}–${Math.min(offset + PAGE_SIZE, kpis.total)} of ${kpis.total}`
                  : "0 results"}
              </span>
              <Button
                variant="secondary"
                disabled={offset + PAGE_SIZE >= kpis.total}
                onClick={() => setOffset(offset + PAGE_SIZE)}
              >
                Next
              </Button>
            </div>
          </div>

          <AsyncContent
            state={listState}
            empty={() => visibleItems.length === 0}
            emptyLabel={
              filtersActive
                ? "No IOCs match the current search/filters — try Reset filters."
                : scope === "tenant"
                  ? "No tenant IOC intelligence recorded yet."
                  : "No global IOC intelligence available."
            }
          >
            {() => (
              <DataConsole
                columns={columns}
                rows={visibleItems}
                rowKey={(r) => r.ioc_id}
                onRowClick={openRow}
                selectedKey={selectedId}
              />
            )}
          </AsyncContent>
        </>
      )}

      <InvestigationDrawer
        open={!!selectedId}
        onClose={closeDrawer}
        title="IOC Detail"
        subtitle={detail?.canonical_key}
        entityId={selectedId ?? undefined}
        fields={
          detailError
            ? [{ label: "Error", value: <span role="alert">{detailError}</span> }]
            : detail
              ? drawerFields
              : [{ label: "Loading", value: "Loading…" }]
        }
      />

      {detail && showAddSource && (
        <AddSourceForm
          iocId={detail.ioc_id}
          onClose={() => setShowAddSource(false)}
          onSaved={(updated) => {
            setShowAddSource(false);
            setDetail(updated);
            listState.reload();
          }}
        />
      )}

      {detail && showAddEvidence && (
        <AddEvidenceForm
          iocId={detail.ioc_id}
          onClose={() => setShowAddEvidence(false)}
          onSaved={(updated) => {
            setShowAddEvidence(false);
            setDetail(updated);
            listState.reload();
          }}
        />
      )}

      {observeOpen && (
        <ObserveIocForm
          scope={observeOpen}
          onClose={() => setObserveOpen(null)}
          onCreated={() => {
            setObserveOpen(null);
            listState.reload();
          }}
        />
      )}
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <div className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">{label}</div>
      <div className="mt-0.5 break-words text-sm text-gray-200">{value}</div>
    </div>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <div className="min-w-[140px]">
      <label className="mb-1 block text-[10px] font-semibold uppercase tracking-wider text-gray-500">{label}</label>
      <select
        aria-label={`${label} filter`}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className={DARK_SELECT_CLASS}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </div>
  );
}

function ObserveIocForm({
  scope,
  onClose,
  onCreated,
}: {
  scope: "tenant" | "global";
  onClose: () => void;
  onCreated: () => void;
}) {
  const [iocType, setIocType] = useState<string>(IOC_TYPE_VALUES[0]);
  const [rawValue, setRawValue] = useState("");
  const [sourceSystem, setSourceSystem] = useState("alienvault_otx");
  const [externalId, setExternalId] = useState("");
  const [confidence, setConfidence] = useState("medium");
  const [weight, setWeight] = useState(0.5);
  const [observedAt, setObservedAt] = useState(() => new Date().toISOString());
  const [entityType, setEntityType] = useState<"" | "SecurityCondition" | "InvestigationCase">("");
  const [entityId, setEntityId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const source_attributions: SourceAttributionInput[] =
        sourceSystem && externalId
          ? [
              {
                source_system: sourceSystem,
                external_id: externalId,
                observed_at: observedAt,
                weight_applied: weight,
                confidence,
              },
            ]
          : [];
      const evidence_citations: EvidenceCitationInput[] =
        entityType && entityId ? [{ entity_type: entityType, entity_id: entityId }] : [];
      const body = { ioc_type: iocType, raw_value: rawValue, source_attributions, evidence_citations };
      if (scope === "tenant") {
        await observeTenantIoc(body);
      } else {
        await observeGlobalIoc(body);
      }
      onCreated();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <FormModal
      title={scope === "tenant" ? "Observe Tenant IOC" : "Observe Global IOC"}
      onClose={onClose}
      contentClassName="w-full max-w-md max-h-[90vh] overflow-y-auto rounded-xl border border-gray-800 bg-gray-900 p-5"
    >
      <form onSubmit={submit} className="space-y-3">
        {error && <ApiErrorPanel message={error} />}
        <FormField label="IOC Type" required>
          <select value={iocType} onChange={(e) => setIocType(e.target.value)} className={DARK_SELECT_CLASS}>
            {IOC_TYPE_VALUES.map((v) => (
              <option key={v} value={v}>
                {v.toUpperCase()}
              </option>
            ))}
          </select>
        </FormField>
        <FormField label="Indicator Value" required hint="Normalized/canonicalized by the backend.">
          <input value={rawValue} onChange={(e) => setRawValue(e.target.value)} required className={DARK_INPUT_CLASS} />
        </FormField>

        <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-3">
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
            Source Attribution (optional — leave provider + reference to attach)
          </p>
          <div className="space-y-3">
            <ProviderSearchSelect value={sourceSystem} onChange={setSourceSystem} />
            <FormField label="External Reference ID" hint="Structured reference from the provider.">
              <input
                value={externalId}
                onChange={(e) => setExternalId(e.target.value)}
                placeholder={IOC_PROVIDER_REFERENCE_PLACEHOLDER[sourceSystem] ?? "e.g. REF-12345"}
                className={DARK_INPUT_CLASS}
              />
            </FormField>
            <ConfidenceStepper value={confidence} onChange={setConfidence} />
            <WeightSlider value={weight} onChange={setWeight} />
            <DateTimeField isoValue={observedAt} onChange={setObservedAt} label="Observed At" />
          </div>
        </div>

        {scope === "tenant" && (
          <div className="rounded-lg border border-gray-800 bg-gray-950/40 p-3">
            <p className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
              Evidence Citation (optional)
            </p>
            <div className="space-y-3">
              <FormField label="Evidence Entity Type" hint="Structured citation — no free-text evidence string.">
                <select
                  value={entityType}
                  onChange={(e) => setEntityType(e.target.value as typeof entityType)}
                  className={DARK_SELECT_CLASS}
                >
                  <option value="">None</option>
                  <option value="SecurityCondition">Security Condition</option>
                  <option value="InvestigationCase">Investigation Case</option>
                </select>
              </FormField>
              {entityType && (
                <FormField label="Evidence Entity ID" required>
                  <input value={entityId} onChange={(e) => setEntityId(e.target.value)} required className={DARK_INPUT_CLASS} />
                </FormField>
              )}
            </div>
          </div>
        )}

        <div className="flex justify-end gap-2 pt-2">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" loading={submitting} loadingLabel="Submitting…">
            Observe
          </Button>
        </div>
      </form>
    </FormModal>
  );
}

function AddSourceForm({
  iocId,
  onClose,
  onSaved,
}: {
  iocId: string;
  onClose: () => void;
  onSaved: (updated: IocDetail) => void;
}) {
  const [sourceSystem, setSourceSystem] = useState("alienvault_otx");
  const [externalId, setExternalId] = useState("");
  const [confidence, setConfidence] = useState("medium");
  const [weight, setWeight] = useState(0.5);
  const [observedAt, setObservedAt] = useState(() => new Date().toISOString());
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const updated = await addSourceAttribution(iocId, {
        source_system: sourceSystem,
        external_id: externalId,
        observed_at: observedAt,
        weight_applied: weight,
        confidence,
      });
      onSaved(updated);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <FormModal
      title="Add Source Attribution"
      onClose={onClose}
      contentClassName="w-full max-w-md max-h-[90vh] overflow-y-auto rounded-xl border border-gray-800 bg-gray-900 p-5"
    >
      <form onSubmit={submit} className="space-y-3">
        {error && <ApiErrorPanel message={error} />}
        <ProviderSearchSelect value={sourceSystem} onChange={setSourceSystem} required />
        <FormField label="External Reference ID" required hint="Structured reference from the provider.">
          <input
            value={externalId}
            onChange={(e) => setExternalId(e.target.value)}
            required
            placeholder={IOC_PROVIDER_REFERENCE_PLACEHOLDER[sourceSystem] ?? "e.g. REF-12345"}
            className={DARK_INPUT_CLASS}
          />
        </FormField>
        <ConfidenceStepper value={confidence} onChange={setConfidence} />
        <WeightSlider value={weight} onChange={setWeight} />
        <DateTimeField isoValue={observedAt} onChange={setObservedAt} label="Observed At" />
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" loading={submitting} loadingLabel="Saving…">
            Add Source
          </Button>
        </div>
      </form>
    </FormModal>
  );
}

function AddEvidenceForm({
  iocId,
  onClose,
  onSaved,
}: {
  iocId: string;
  onClose: () => void;
  onSaved: (updated: IocDetail) => void;
}) {
  const [entityType, setEntityType] = useState<"SecurityCondition" | "InvestigationCase">(
    "SecurityCondition"
  );
  const [entityId, setEntityId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const updated = await addEvidenceCitation(iocId, { entity_type: entityType, entity_id: entityId });
      onSaved(updated);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <FormModal title="Add Evidence Citation" onClose={onClose}>
      <form onSubmit={submit} className="space-y-3">
        {error && <ApiErrorPanel message={error} />}
        <FormField label="Entity Type" required>
          <select
            value={entityType}
            onChange={(e) => setEntityType(e.target.value as typeof entityType)}
            className={DARK_SELECT_CLASS}
          >
            <option value="SecurityCondition">Security Condition</option>
            <option value="InvestigationCase">Investigation Case</option>
          </select>
        </FormField>
        <FormField label="Entity ID" required hint="Structured reference — no free-text evidence string.">
          <input value={entityId} onChange={(e) => setEntityId(e.target.value)} required className={DARK_INPUT_CLASS} />
        </FormField>
        <div className="flex justify-end gap-2 pt-2">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" variant="primary" loading={submitting} loadingLabel="Saving…">
            Add Evidence
          </Button>
        </div>
      </form>
    </FormModal>
  );
}
