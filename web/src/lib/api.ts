// Fetch wrapper and data hooks.

import { useCallback, useEffect, useRef, useState } from "react";
import type { ApiError } from "../../../src/shared/api.ts";

export class HttpError extends Error {
  readonly status: number;
  readonly body: Partial<ApiError>;
  constructor(status: number, body: Partial<ApiError>) {
    super(String(body?.error || `Request failed (${status})`));
    this.status = status;
    this.body = body;
  }
}

const listeners = new Set<(e: HttpError) => void>();
/** Lets the app shell react to sign-in, setup and unknown-scope errors from any request. */
export const onApiError = (fn: (e: HttpError) => void) => {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
};

export async function api<T = unknown>(path: string, init: { method?: string; body?: unknown; signal?: AbortSignal } = {}): Promise<T> {
  const res = await fetch(path, {
    method: init.method || "GET",
    headers: init.body !== undefined ? { "content-type": "application/json" } : undefined,
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
    credentials: "same-origin",
    signal: init.signal,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new HttpError(res.status, body);
    if (body?.code) listeners.forEach((l) => l(err));
    throw err;
  }
  return body as T;
}

/**
 * Fetches `path` and refetches when it or `key` changes. A newer request
 * cancels an older one, so a slow response never overwrites a newer view.
 * `reload` refetches while keeping the previous data on screen.
 */
export function useApi<T>(path: string | null, key: unknown = null) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<Error | null>(null);
  const [loading, setLoading] = useState(path != null);
  const inflight = useRef<AbortController | null>(null);

  const reload = useCallback(async () => {
    inflight.current?.abort();
    if (!path) {
      setLoading(false);
      return;
    }
    const ctl = new AbortController();
    inflight.current = ctl;
    setLoading(true);
    try {
      const d = await api<T>(path, { signal: ctl.signal });
      if (!ctl.signal.aborted) {
        setData(d);
        setError(null);
      }
    } catch (e) {
      if (!ctl.signal.aborted) setError(e as Error);
    } finally {
      if (!ctl.signal.aborted) setLoading(false);
    }
  }, [path]);

  // biome-ignore lint/correctness/useExhaustiveDependencies: `key` is an explicit refetch trigger, compared by value
  useEffect(() => {
    void reload();
    return () => inflight.current?.abort();
  }, [reload, JSON.stringify(key)]);
  return { data, error, loading, reload, setData };
}
