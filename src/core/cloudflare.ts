// Read-only Cloudflare API client. Every call is recorded under a coverage label
// so the UI can say exactly which data a scan could and couldn't read.
//
// Limits: at most 24 requests in flight (Cloudflare limits rate, not concurrency), and a sliding window that stays under
// Cloudflare's 1200 requests per 5 minutes per token, shared by every account scanned with that token. A 429 pauses
// all of the token's requests until Retry-After; 5xx and network errors are retried twice.

import { createHash } from "node:crypto";
import type { Api, CoverageEntry } from "./types.ts";
import { SOURCES, type SourceKey } from "./sources.ts";

const API = "https://api.cloudflare.com/client/v4";
const MAX_IN_FLIGHT = 24;
const WINDOW_MS = 5 * 60_000;
/** Requests per token per window. Mutable only so the mocked API (dev/mock), which has no limit, can lift it. */
export const rateLimit = { perWindow: 1100 };
const TIMEOUT_MS = 30_000;

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** What makes an optional read "not set up" rather than unreadable: a status, a message pattern, or a test of both. */
export type Absent = number | RegExp | ((status: number, message: string) => boolean);

interface CursorOptions {
  key?: string;
  absent?: Absent[];
  perPage?: number;
  max?: number;
}

/** Request times and any 429 pause, per token: Cloudflare's limit is per token, not per account. */
interface TokenWindow {
  stamps: number[];
  pausedUntil: number;
}
const windows = new Map<string, TokenWindow>();

function windowFor(token: string): TokenWindow {
  const key = createHash("sha256").update(token).digest("hex");
  let w = windows.get(key);
  if (!w) windows.set(key, (w = { stamps: [], pausedUntil: 0 }));
  return w;
}

export class CloudflareClient {
  readonly accountId: string;
  calls = 0;
  readonly coverage = new Map<SourceKey, CoverageEntry>();
  #token: string;
  #inFlight = 0;
  #queue: (() => void)[] = [];
  readonly #window: TokenWindow;

  constructor(token: string, accountId: string) {
    this.#token = token;
    this.accountId = accountId;
    this.#window = windowFor(token);
  }

  async raw(path: string, init: RequestInit = {}): Promise<Api> {
    await this.#acquire();
    try {
      for (let attempt = 0; ; attempt++) {
        this.calls++;
        this.#window.stamps.push(Date.now());
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
          const wait = Math.min(Number(res.headers.get("retry-after")) || 2 * (attempt + 1), 60) * 1000;
          // Everything else on this token would get 429 too: hold it all until Cloudflare says to resume.
          this.#window.pausedUntil = Math.max(this.#window.pausedUntil, Date.now() + wait);
          await sleep(wait);
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
  async getOptional<T = Api>(source: SourceKey, path: string, absent: Absent[] = []): Promise<T | null | undefined> {
    try {
      const body = await this.raw(path);
      this.note(source, true);
      return body.result as T;
    } catch (e) {
      return this.#optionalFailure(source, e, absent);
    }
  }

  /**
   * Cursor pagination (R2 and newer endpoints): follows result_info.cursor until it runs out.
   * `key` picks the list out of an object result ({ buckets: [...] }). Absent rules as getOptional.
   */
  async listCursor<T = Api>(
    source: SourceKey,
    path: string,
    { key, absent = [], perPage = 1000, max = 10_000 }: CursorOptions = {},
  ): Promise<T[] | null | undefined> {
    const out: T[] = [];
    try {
      let cursor = "";
      do {
        const sep = path.includes("?") ? "&" : "?";
        const body = await this.raw(`${path}${sep}per_page=${perPage}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
        const items = (key ? body.result?.[key] : body.result) as T[] | undefined;
        if (!Array.isArray(items) || !items.length) break;
        out.push(...items);
        cursor = String(body.result_info?.cursor || "");
      } while (cursor && out.length < max);
      this.note(source, true);
      return out;
    } catch (e) {
      return this.#optionalFailure(source, e, absent);
    }
  }

  /** A status, or a message, that means "this product isn't set up" (null) rather than "not allowed" (undefined). */
  #optionalFailure(source: SourceKey, e: unknown, absent: Absent[]): null | undefined {
    const { status, message } = e as ApiError;
    if (status === 404 || absent.some((a) => (typeof a === "number" ? a === status : typeof a === "function" ? a(status, message) : a.test(message)))) {
      this.note(source, true);
      return null;
    }
    this.note(source, false, e);
    return undefined;
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
        // Endpoints report total_pages, total_count, or neither; a full page with neither means there may be more.
        const info = body.result_info;
        const more = info?.total_pages ? page < info.total_pages : info?.total_count ? out.length < info.total_count : items.length === perPage;
        if (!items.length || !more) break;
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
    const w = this.#window;
    if (w.pausedUntil > Date.now()) await sleep(w.pausedUntil - Date.now());
    const cutoff = Date.now() - WINDOW_MS;
    while (w.stamps.length && w.stamps[0] < cutoff) w.stamps.shift();
    if (w.stamps.length >= rateLimit.perWindow) await sleep(w.stamps[0] + WINDOW_MS - Date.now() + 50);
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
/**
 * Public DNS lookups since the last reset. Scans run one at a time, so a scan resets this before
 * its lookups and reads it after, to tell "no record" apart from "couldn't ask".
 */
export const dohStats = { lookups: 0, failed: 0 };

export async function doh(name: string, type = "A"): Promise<DohAnswer> {
  dohStats.lookups++;
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, {
      headers: { accept: "application/dns-json" },
      signal: AbortSignal.timeout(10_000),
    });
    const j = (await res.json()) as Api;
    return { status: j.Status, answers: (j.Answer || []).map((a: Api) => ({ type: a.type, data: a.data })) };
  } catch {
    dohStats.failed++;
    return { status: -1, answers: [] };
  }
}
