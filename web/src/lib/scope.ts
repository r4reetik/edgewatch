// The dashboard scope: "all", "e:<entity id>" or "a:<account id>". The URL is
// the source of truth (?scope=), so links say what they show; the last choice
// is remembered per browser and used when a URL has none.

import { useCallback } from "react";
import { defaultScopeKey, resolveScope, type ResolvedScope } from "../../../src/shared/scope.ts";
import type { Session, SessionAccount, SessionEntity } from "../../../src/shared/api.ts";
import { setParams, useLocation } from "./router.ts";

const STORAGE_KEY = "edgewatch-scope";

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
    setParams({ scope: s });
  }, []);
  return [fromUrl || remembered(), set];
}

/** Writes the resolved scope into the URL when it isn't there yet (first load, old links). */
export function adoptScope(key: string) {
  if (new URLSearchParams(location.search).get("scope") !== key) setParams({ scope: key });
  remember(key);
}

export const withScope = (path: string, scope: string) => `${path}${path.includes("?") ? "&" : "?"}scope=${encodeURIComponent(scope)}`;
