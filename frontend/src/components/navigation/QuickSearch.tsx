"use client";

import { Clock, Search, X } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { NavGroup, NavItem } from "@/components/navigation/navConfig";

const RECENT_COMMANDS_KEY = "redforge_recent_commands";
const MAX_RECENT_COMMANDS = 5;

function readRecentCommands(): string[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(RECENT_COMMANDS_KEY);
    return raw ? (JSON.parse(raw) as string[]) : [];
  } catch {
    return [];
  }
}

function pushRecentCommand(href: string): void {
  if (typeof window === "undefined") return;
  try {
    const next = [href, ...readRecentCommands().filter((h) => h !== href)].slice(
      0,
      MAX_RECENT_COMMANDS
    );
    window.localStorage.setItem(RECENT_COMMANDS_KEY, JSON.stringify(next));
  } catch {
    // localStorage unavailable — recent commands degrade to session-only.
  }
}

interface QuickSearchProps {
  groups: NavGroup[];
  onNavigate: (href: string) => void;
}

/**
 * Command Palette — `Ctrl+K` / `Cmd+K` (the standard cross-platform
 * shortcut most enterprise SaaS products already use). Full keyboard
 * navigation: Up/Down moves the roving `role="option"` highlight,
 * Enter opens the highlighted result, Escape closes — a real gap
 * fixed here (results were previously mouse/click only). Searches every
 * visible module label (only from `groups`, which the caller has
 * already RBAC-filtered — this component never sees an item the user
 * can't access) and tracks the last 5 opened commands for a "Recent
 * Commands" section when no query is typed.
 *
 * Scoped honestly to module navigation only — this is NOT a fuzzy
 * search across findings/investigations/credentials/etc. by title or
 * ID. Opening the *list page* for those entity types (Findings,
 * Investigations, Credential Vault, Attack Paths, AI Targets) is
 * already fully covered because each is its own nav item and
 * therefore already searchable here. Searching *inside* those entity
 * types (e.g. "find the finding titled X") would require confirming
 * or building real search-capable list endpoints per entity type —
 * not done in this pass rather than faked with a client-side filter
 * over an unbounded list.
 */
export function QuickSearch({ groups, onNavigate }: QuickSearchProps) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [recentHrefs, setRecentHrefs] = useState<string[]>([]);
  const [highlighted, setHighlighted] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setOpen(true);
      }
      if (e.key === "Escape") setOpen(false);
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (open) {
      setQuery("");
      setHighlighted(0);
      setRecentHrefs(readRecentCommands());
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const itemByHref = useMemo(() => {
    const map = new Map<string, { group: string; item: NavItem }>();
    for (const group of groups) {
      for (const item of group.items) map.set(item.href, { group: group.title, item });
    }
    return map;
  }, [groups]);

  const results: { group: string; item: NavItem }[] = useMemo(() => {
    if (!query.trim()) return [];
    const q = query.toLowerCase();
    return groups.flatMap((group) =>
      group.items.filter((item) => item.label.toLowerCase().includes(q)).map((item) => ({ group: group.title, item }))
    );
  }, [groups, query]);

  const recentCommands = recentHrefs
    .map((href) => itemByHref.get(href))
    .filter((entry): entry is { group: string; item: NavItem } => entry !== undefined);

  const activeList = query.trim() ? results : recentCommands;

  useEffect(() => {
    setHighlighted(0);
  }, [query]);

  useEffect(() => {
    const el = listRef.current?.querySelector('[aria-selected="true"]');
    el?.scrollIntoView?.({ block: "nearest" });
  }, [highlighted]);

  function navigate(href: string) {
    setOpen(false);
    pushRecentCommand(href);
    onNavigate(href);
  }

  function onInputKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (activeList.length === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setHighlighted((i) => (i + 1) % activeList.length);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setHighlighted((i) => (i - 1 + activeList.length) % activeList.length);
    } else if (e.key === "Enter") {
      e.preventDefault();
      const entry = activeList[highlighted];
      if (entry) navigate(entry.item.href);
    }
  }

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="flex w-full items-center gap-2 rounded-lg border border-gray-800 bg-gray-950 px-3 py-1.5 text-left text-sm text-gray-500 hover:border-gray-700"
      >
        <Search className="h-3.5 w-3.5" aria-hidden="true" />
        <span className="flex-1">Command palette</span>
        <kbd className="rounded border border-gray-700 px-1.5 py-0.5 text-[10px] text-gray-600">⌘K</kbd>
      </button>

      {open && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-24"
          onClick={() => setOpen(false)}
        >
          <div
            className="w-full max-w-lg rounded-xl border border-gray-800 bg-gray-900 shadow-2xl"
            onClick={(e) => e.stopPropagation()}
            role="dialog"
            aria-label="Quick search"
          >
            <div className="flex items-center gap-2 border-b border-gray-800 px-4 py-3">
              <Search className="h-4 w-4 text-gray-500" aria-hidden="true" />
              <input
                ref={inputRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={onInputKeyDown}
                placeholder="Search modules…"
                className="flex-1 bg-transparent text-sm text-gray-200 placeholder:text-gray-600 focus:outline-none"
                role="combobox"
                aria-expanded={activeList.length > 0}
                aria-controls="quick-search-listbox"
                aria-activedescendant={activeList[highlighted] ? `quick-search-option-${highlighted}` : undefined}
              />
              <button type="button" onClick={() => setOpen(false)} aria-label="Close search">
                <X className="h-4 w-4 text-gray-600 hover:text-gray-300" aria-hidden="true" />
              </button>
            </div>
            <div className="max-h-80 overflow-y-auto p-2" role="listbox" id="quick-search-listbox" ref={listRef}>
              {!query.trim() && recentCommands.length > 0 && (
                <>
                  <div className="px-3 pb-1 pt-1 text-[10px] font-semibold uppercase tracking-widest text-gray-600">
                    Recent Commands
                  </div>
                  {recentCommands.map(({ group, item }, i) => (
                    <button
                      key={item.href}
                      id={`quick-search-option-${i}`}
                      role="option"
                      aria-selected={i === highlighted}
                      type="button"
                      onClick={() => navigate(item.href)}
                      onMouseEnter={() => setHighlighted(i)}
                      className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm ${
                        i === highlighted ? "bg-gray-800 text-gray-100" : "text-gray-300"
                      }`}
                    >
                      <Clock className="h-3.5 w-3.5 text-gray-600" aria-hidden="true" />
                      <span className="flex-1">{item.label}</span>
                      <span className="text-xs text-gray-600">{group}</span>
                    </button>
                  ))}
                </>
              )}
              {query.trim() && results.length === 0 && (
                <p className="px-3 py-6 text-center text-sm text-gray-600">No modules match &ldquo;{query}&rdquo;.</p>
              )}
              {results.map(({ group, item }, i) => (
                <button
                  key={item.href}
                  id={`quick-search-option-${i}`}
                  role="option"
                  aria-selected={i === highlighted}
                  type="button"
                  onClick={() => navigate(item.href)}
                  onMouseEnter={() => setHighlighted(i)}
                  className={`flex w-full items-center gap-3 rounded-lg px-3 py-2 text-left text-sm ${
                    i === highlighted ? "bg-gray-800 text-gray-100" : "text-gray-300"
                  }`}
                >
                  <span className="text-base">{item.icon}</span>
                  <span className="flex-1">{item.label}</span>
                  <span className="text-xs text-gray-600">{group}</span>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
