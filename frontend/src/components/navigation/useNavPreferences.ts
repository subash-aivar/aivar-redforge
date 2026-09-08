"use client";

import { useCallback, useEffect, useState } from "react";

const FAVORITES_KEY = "redforge_nav_favorites";
const RECENTS_KEY = "redforge_nav_recents";
const COLLAPSED_KEY = "redforge_nav_collapsed_groups";
const MAX_RECENTS = 6;

function readJson<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch {
    return fallback;
  }
}

function writeJson(key: string, value: unknown): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // localStorage unavailable (private browsing, quota) — favorites/
    // recents/collapse-state degrade to session-only, never crash nav.
  }
}

/**
 * Client-only navigation preferences: favorites, recently-visited
 * pages, and per-group collapse state. All three are pure UX
 * conveniences layered on top of `NAV_GROUPS` — none of them affect
 * which items are visible (that's `can()`'s job, untouched) or which
 * routes exist.
 */
export function useNavPreferences(pathname: string) {
  const [favorites, setFavorites] = useState<string[]>([]);
  const [recents, setRecents] = useState<string[]>([]);
  const [collapsedGroups, setCollapsedGroups] = useState<string[]>([]);

  useEffect(() => {
    setFavorites(readJson(FAVORITES_KEY, []));
    setRecents(readJson(RECENTS_KEY, []));
    setCollapsedGroups(readJson(COLLAPSED_KEY, []));
  }, []);

  useEffect(() => {
    if (!pathname) return;
    setRecents((prev) => {
      const next = [pathname, ...prev.filter((p) => p !== pathname)].slice(0, MAX_RECENTS);
      writeJson(RECENTS_KEY, next);
      return next;
    });
  }, [pathname]);

  const toggleFavorite = useCallback((href: string) => {
    setFavorites((prev) => {
      const next = prev.includes(href) ? prev.filter((h) => h !== href) : [...prev, href];
      writeJson(FAVORITES_KEY, next);
      return next;
    });
  }, []);

  const toggleGroupCollapsed = useCallback((title: string) => {
    setCollapsedGroups((prev) => {
      const next = prev.includes(title) ? prev.filter((t) => t !== title) : [...prev, title];
      writeJson(COLLAPSED_KEY, next);
      return next;
    });
  }, []);

  return { favorites, recents, collapsedGroups, toggleFavorite, toggleGroupCollapsed };
}
