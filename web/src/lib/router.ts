// A small history-API router; the server falls back to index.html.
// The dashboard scope (?scope=) is carried across navigations, so every page's
// URL says what it shows and can be shared as is.

import { useSyncExternalStore } from "react";

const listeners = new Set<() => void>();
export const emitRoute = () => listeners.forEach((l) => l());
window.addEventListener("popstate", emitRoute);

const current = () => location.pathname + location.search;

/** Keeps the current ?scope= on a same-app link that doesn't set its own. */
export function carryScope(to: string): string {
  const scope = new URLSearchParams(location.search).get("scope");
  if (!scope || !to.startsWith("/")) return to;
  const url = new URL(to, location.origin);
  if (!url.searchParams.has("scope")) url.searchParams.set("scope", scope);
  return url.pathname + url.search + url.hash;
}

export function navigate(to: string, { replace = false } = {}) {
  const target = carryScope(to);
  if (target === current()) return;
  history[replace ? "replaceState" : "pushState"](null, "", target);
  (document.getElementById("scroll-root") || document.scrollingElement)?.scrollTo(0, 0);
  emitRoute();
}

export function useLocation() {
  const href = useSyncExternalStore((cb) => {
    listeners.add(cb);
    return () => listeners.delete(cb);
  }, current);
  const url = new URL(href, location.origin);
  return { path: url.pathname, params: url.searchParams, href };
}

/** Updates query params in place without adding history entries. */
export function setParams(next: Record<string, string | null | undefined>) {
  const url = new URL(location.href);
  for (const [k, v] of Object.entries(next)) {
    if (v == null || v === "") url.searchParams.delete(k);
    else url.searchParams.set(k, v);
  }
  const to = url.pathname + url.search;
  if (to !== current()) {
    history.replaceState(null, "", to);
    emitRoute();
  }
}

/** Click handler for same-app links so they route without a reload (modifier clicks open a tab). */
export function linkHandler(to: string) {
  return (e: React.MouseEvent) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    navigate(to);
  };
}

/** href and onClick for an in-app link, with the scope carried. */
export const link = (to: string) => ({ href: carryScope(to), onClick: linkHandler(to) });
