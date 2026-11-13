// The dashboard scope: "all", "e:<entity id>", "a:<account id>" or a ticked set of
// accounts ("s:<id>,<id>"). The URL is the source of truth (?scope=), so links say
// what they show; the last choice is remembered per browser and used when a URL
// has none.

import { useCallback } from "react";
import { defaultScopeKey, keyForAccounts, resolveScope, type ResolvedScope } from "../../../src/shared/scope.ts";
import type { Session, SessionAccount, SessionEntity } from "../../../src/shared/api.ts";
import { setParams, useLocation } from "./router.ts";

const STORAGE_KEY = "keelson-scope";

export type View = ResolvedScope<SessionAccount, SessionEntity>;

export const resolveView = (session: Session, key: string): View | null => resolveScope(session.accounts || [], session.entities || [], key);
export const defaultScope = (session: Session): string => defaultScopeKey(session.accounts || [], session.entities || []);

const remembered = () => {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
};
const remember = (s: string) => {
  try {
    localStorage.setItem(STORAGE_KEY, s);
  } catch {
    /* storage unavailable */
  }
};

/** The scope in the URL, else the remembered one (null until chosen). */
export function useScopeKey(): [string | null, (s: string) => void] {
  const { params } = useLocation();
  const fromUrl = params.get("scope");
  const set = useCallback((s: string) => {
    remember(s);
    // An account filter belongs to the view it was picked in; another view may not contain that account.
    setParams({ scope: s, account: null });
  }, []);
  return [fromUrl || remembered(), set];
}

/** Writes the resolved scope into the URL when it isn't there yet (first load, old links). */
export function adoptScope(key: string) {
  if (new URLSearchParams(location.search).get("scope") !== key) setParams({ scope: key });
  remember(key);
}

/**
 * The view after ticking or unticking some accounts in the pickers, as a scope key. Null when nothing changes:
 * the last account can't be unticked, since a view always shows something.
 *
 * Entities stay apart: ticking an account of an entity that is kept separate (or ticking another entity's
 * account while one of those is in view) starts a new selection in that entity instead of combining them.
 */
export function toggleAccounts(session: Session, view: View, ids: string[], on: boolean): string | null {
  const accounts = session.accounts || [];
  const entities = session.entities || [];
  const current = new Set(view.accounts.map((a) => a.id));
  for (const id of ids) on ? current.add(id) : current.delete(id);
  let next = accounts.filter((a) => current.has(a.id));
  const owners = entities.filter((e) => next.some((a) => a.entityId === e.id));
  if (on && owners.length > 1 && owners.some((e) => !e.includeInAll)) {
    const home = accounts.find((a) => a.id === ids[0])?.entityId;
    next = next.filter((a) => a.entityId === home);
  }
  const key = keyForAccounts(
    accounts,
    entities,
    next.map((a) => a.id),
  );
  return key && key !== view.key ? key : null;
}

export const withScope = (path: string, scope: string) => `${path}${path.includes("?") ? "&" : "?"}scope=${encodeURIComponent(scope)}`;
