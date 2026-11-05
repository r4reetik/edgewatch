// Read-only Cloudflare API client. Every call is recorded under a coverage label
// so the UI can say exactly which data a scan could and couldn't read.
//
// Limits: at most 24 requests in flight (Cloudflare limits rate, not concurrency), and a sliding window that stays under
// Cloudflare's 1200 requests per 5 minutes per token. 429s are retried with
// Retry-After; 5xx and network errors are retried twice.

import type { Api, CoverageEntry } from "./types.ts";
import { SOURCES, type SourceKey } from "./sources.ts";

const API = "https://api.cloudflare.com/client/v4";
const MAX_IN_FLIGHT = 24;
const WINDOW_MS = 5 * 60_000;
const WINDOW_LIMIT = 1100;
const TIMEOUT_MS = 30_000;

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export class CloudflareClient {
  readonly accountId: string;
  calls = 0;
  readonly coverage = new Map<SourceKey, CoverageEntry>();
  #token: string;
  #inFlight = 0;
  #queue: (() => void)[] = [];
  #stamps: number[] = [];

  constructor(token: string, accountId: string) {
    this.#token = token;
    this.accountId = accountId;
  }

  async raw(path: string, init: RequestInit = {}): Promise<Api> {
    await this.#acquire();
    try {
      for (let attempt = 0; ; attempt++) {
        this.calls++;
        this.#stamps.push(Date.now());
        let res: Response;
        try {
          res = await fetch(API + path, {
            ...init,
            signal: AbortSignal.timeout(TIMEOUT_MS),
            headers: { Authorization: `Bearer ${this.#token}`, "Content-Type": "application/json", ...(init.headers || {}) },
          });
        } catch (e) {
          if (attempt < 2) {
            await sleep(1000 * (attempt + 1));
            continue;
          }
          throw new ApiError(0, `Network error: ${(e as Error).message}`);
        }
        if (res.status === 429 && attempt < 4) {
          const wait = Number(res.headers.get("retry-after")) || 2 * (attempt + 1);
          await sleep(Math.min(wait, 60) * 1000);
          continue;
        }
        if (res.status >= 500 && attempt < 2) {
          await sleep(1000 * (attempt + 1));
          continue;
        }
        let body: Api = null;
        try {
          body = await res.json();
        } catch {
          /* non-JSON body */
        }
        if (!res.ok || body?.success === false) {
          const message = body?.errors?.map((e: Api) => e.message).join("; ") || res.statusText || "Request failed";
          throw new ApiError(res.status, message);
        }
        return body;
      }
    } finally {
      this.#release();
    }
  }

  /** GET a path and record coverage for `source`. Returns null when unreadable. */
  async get<T = Api>(source: SourceKey, path: string): Promise<T | null> {
    try {
      const body = await this.raw(path);
      this.note(source, true);
      return body.result as T;
    } catch (e) {
      this.note(source, false, e);
      return null;
    }
  }

  /**
   * Like get(), but a "not configured" answer (404, or one of `absent`, e.g. a
   * 400 for a feature the plan lacks) returns `null` and isn't a gap. Unreadable
   * returns `undefined`.
   */
  async getOptional<T = Api>(source: SourceKey, path: string, absent: (number | RegExp)[] = []): Promise<T | null | undefined> {
    try {
      const body = await this.raw(path);
      this.note(source, true);
      return body.result as T;
    } catch (e) {
      const { status, message } = e as ApiError;
      // A status, or a message, that means "this product isn't set up" rather than "not allowed".
      if (status === 404 || absent.some((a) => (typeof a === "number" ? a === status : a.test(message)))) {
        this.note(source, true);
        return null;
      }
      this.note(source, false, e);
      return undefined;
    }
  }

  /** Page-number pagination, used by most v4 list endpoints. */
  async list<T = Api>(source: SourceKey, path: string, { perPage = 100, max = 10_000 } = {}): Promise<T[] | null> {
    const out: T[] = [];
    try {
      for (let page = 1; out.length < max; page++) {
        const sep = path.includes("?") ? "&" : "?";
        const body = await this.raw(`${path}${sep}per_page=${perPage}&page=${page}`);
        const items: T[] = Array.isArray(body.result) ? body.result : [];
        out.push(...items);
        const info = body.result_info;
        if (!info || items.length === 0 || page >= (info.total_pages || 1)) break;
      }
      this.note(source, true);
      return out;
    } catch (e) {
      this.note(source, false, e);
      return null;
    }
  }

  async graphql(query: string, variables: Record<string, unknown>): Promise<Api> {
    const body = await this.raw("/graphql", { method: "POST", body: JSON.stringify({ query, variables }) });
    if (body.errors?.length) throw new ApiError(400, body.errors.map((e: Api) => e.message).join("; "));
    return body.data;
  }

  /** Records whether a source was readable. The first failure sticks: a later success on another zone shouldn't hide it. */
  note(source: SourceKey, ok: boolean, err?: unknown): void {
    const prev = this.coverage.get(source);
    if (prev && !prev.ok) return;
    const { label, permission } = SOURCES[source];
    if (ok) this.coverage.set(source, { key: source, label, permission, ok: true });
    else
      this.coverage.set(source, {
        key: source,
        label,
        permission,
        ok: false,
        status: (err as ApiError)?.status || 0,
        message: String((err as Error)?.message || err).slice(0, 200),
      });
  }

  async #acquire(): Promise<void> {
    while (this.#inFlight >= MAX_IN_FLIGHT) await new Promise<void>((r) => this.#queue.push(r));
    this.#inFlight++;
    const cutoff = Date.now() - WINDOW_MS;
    while (this.#stamps.length && this.#stamps[0] < cutoff) this.#stamps.shift();
    if (this.#stamps.length >= WINDOW_LIMIT) await sleep(this.#stamps[0] + WINDOW_MS - Date.now() + 50);
  }

  #release(): void {
    this.#inFlight--;
    this.#queue.shift()?.();
  }
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, Math.max(0, ms)));

/** Runs `fn` over `items` with at most `limit` in flight, preserving order. */
export async function pool<T, R>(items: T[], limit: number, fn: (item: T, i: number) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return results;
}

export interface DohAnswer {
  status: number;
  answers: { type: number; data: string }[];
}

/** DNS-over-HTTPS lookup against 1.1.1.1. status 3 = NXDOMAIN, -1 = lookup failed. */
export async function doh(name: string, type = "A"): Promise<DohAnswer> {
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(10_000),
    });
    const j = (await res.json()) as Api;
    return { status: j.Status, answers: (j.Answer || []).map((a: Api) => ({ type: a.type, data: a.data })) };
  } catch {
    return { status: -1, answers: [] };
  }
}
