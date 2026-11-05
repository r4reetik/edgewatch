// The app shell's shared state: session, scope, scan status. Pages read it with
// useShell(); useScopedApi() fetches scoped data and refetches after each scan.

import { createContext, useContext } from "react";
import { useApi, withScope, type ScanStatus, type Session, type View } from "./lib.ts";

export interface Shell {
  session: Session;
  refreshSession: () => Promise<void>;
  status: ScanStatus | null;
  /** Increments whenever a scan finishes, so pages refetch. */
  dataVersion: number;
  /** Scans the current view, or the given scope key (an account's row scans just that account); `every` scans every account in every entity. */
  startScan: (scopeKey?: string, opts?: { every?: boolean }) => Promise<void>;
  /** What the dashboard is looking at: all included accounts, one entity, or one account. */
  view: View;
  setScope: (key: string) => void;
  /** Adds the current scope to an API path. */
  scoped: (path: string) => string;
  /** More than one account is in view, so pages show which account each row belongs to. */
  multi: boolean;
}

export const ShellContext = createContext<Shell | null>(null);

export function useShell(): Shell {
  const s = useContext(ShellContext);
  if (!s) throw new Error("useShell() outside the app shell");
  return s;
}

/** GET a scoped API path; refetches when the scope changes, a scan finishes, or `key` changes. */
export function useScopedApi<T>(path: string | null, key: unknown = null) {
  const { view, dataVersion } = useShell();
  return useApi<T>(path ? withScope(path, view.key) : null, [dataVersion, key]);
}
