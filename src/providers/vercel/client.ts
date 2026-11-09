// Read-only Vercel REST client. It only ever sends GET (test/vercel.test.ts fails on
// anything else), because a Vercel token can't be limited to reading. Every call is
// recorded under a coverage label, like the Cloudflare client.
//
// Limits: at most 8 requests in flight. A 429 pauses every request on the token
// until the reset Vercel names; 5xx and network errors are retried twice.

import { createHash } from "node:crypto";
import { VERCEL_SOURCES, type VercelScope, type VercelSourceKey } from "./sources.ts";
import type { Coverage } from "../../shared/api.ts";

export const VERCEL_API = "https://api.vercel.com";
const MAX_IN_FLIGHT = 8;
const TIMEOUT_MS = 30_000;
/** A raw Vercel payload; inventory.ts turns it into the typed shapes in types.ts. */
export type Json = any;

export class VercelError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** A 429 on one account's scan holds every request made with the same token. */
const pauses = new Map<string, number>();
const tokenKey = (t: string) => createHash("sha256").update(t).digest("hex");

export class VercelClient {
  /** The team, or null for the token owner's personal account. */
  readonly team: VercelScope;
  calls = 0;
  readonly coverage = new Map<VercelSourceKey, Coverage & { key: VercelSourceKey }>();
  readonly #token: string;
  readonly #key: string;
  #inFlight = 0;
  #queue: (() => void)[] = [];

  constructor(token: string, team: VercelScope) {
    this.#token = token;
    this.#key = tokenKey(token);
    this.team = team;
  }

  /** Adds the team to a path, so the request reads the team's data rather than the personal account's. */
  path(p: string): string {
    if (!this.team || /[?&]teamId=/.test(p) || p.startsWith("/v2/user") || p.startsWith("/v6/user/tokens") || p.startsWith("/v2/teams?")) return p;
    return `${p}${p.includes("?") ? "&" : "?"}teamId=${encodeURIComponent(this.team)}`;
  }

  /** GET a path (already scoped by `path()` or not team-specific). Throws VercelError. */
  async raw(path: string): Promise<Json> {
    await this.#acquire();
    try {
      for (let attempt = 0; ; attempt++) {
        this.calls++;
        let res: Response;
        try {
          res = await fetch(VERCEL_API + path, {
            method: "GET",
            signal: AbortSignal.timeout(TIMEOUT_MS),
            headers: { Authorization: `Bearer ${this.#token}`, Accept: "application/json" },
          });
        } catch (e) {
          if (attempt < 2) {
            await sleep(1000 * (attempt + 1));
            continue;
          }
          throw new VercelError(0, `Network error: ${(e as Error).message}`);
        }
        if (res.status === 429 && attempt < 4) {
          // Vercel sends the reset time in seconds since the epoch.
          const reset = Number(res.headers.get("x-ratelimit-reset")) * 1000;
          const wait = Math.min(Math.max(reset - Date.now(), (Number(res.headers.get("retry-after")) || 2 * (attempt + 1)) * 1000), 60_000);
          pauses.set(this.#key, Math.max(pauses.get(this.#key) || 0, Date.now() + wait));
          await sleep(wait);
          continue;
        }
        if (res.status >= 500 && attempt < 2) {
          await sleep(1000 * (attempt + 1));
          continue;
        }
        let body: Json = null;
        try {
          body = await res.json();
        } catch {
          /* non-JSON body */
        }
        if (!res.ok) throw new VercelError(res.status, String(body?.error?.message || res.statusText || "Request failed"));
        return body;
      }
    } finally {
      this.#release();
    }
  }

  /** GET with coverage: null when the token can't read it. */
  async get<T = Json>(source: VercelSourceKey, path: string): Promise<T | null> {
    try {
      const body = await this.raw(this.path(path));
      this.note(source, true);
      return body as T;
    } catch (e) {
      this.note(source, false, e);
      return null;
    }
  }

  /**
   * Like get(), but a 404 means "not set up" (null) rather than unreadable (undefined),
   * and isn't a coverage gap.
   */
  async getOptional<T = Json>(source: VercelSourceKey, path: string): Promise<T | null | undefined> {
    try {
      const body = await this.raw(this.path(path));
      this.note(source, true);
      return body as T;
    } catch (e) {
      if ((e as VercelError).status === 404) {
        this.note(source, true);
        return null;
      }
      this.note(source, false, e);
      return undefined;
    }
  }

  /**
   * Vercel's timestamp pagination: each page names the `until` for the next. `key` picks the list
   * out of the body ({ projects: [...] }); some endpoints answer with a bare array.
   */
  async list<T = Json>(source: VercelSourceKey, path: string, key: string, { limit = 100, max = 5000, cursor = "until" } = {}): Promise<T[] | null> {
    const out: T[] = [];
    try {
      let next: string | number | null = null;
      do {
        const sep = path.includes("?") ? "&" : "?";
        const body: Json = await this.raw(this.path(`${path}${sep}limit=${limit}${next != null ? `&${cursor}=${encodeURIComponent(String(next))}` : ""}`));
        const items: T[] = Array.isArray(body) ? body : Array.isArray(body?.[key]) ? body[key] : [];
        out.push(...items);
        next = Array.isArray(body) || !items.length ? null : (body?.pagination?.next ?? null);
      } while (next != null && out.length < max);
      this.note(source, true);
      return out;
    } catch (e) {
      this.note(source, false, e);
      return null;
    }
  }

  /** Records whether a source was readable. The first failure sticks, as in the Cloudflare client. */
  note(source: VercelSourceKey, ok: boolean, err?: unknown): void {
    const prev = this.coverage.get(source);
    if (prev && !prev.ok) return;
    const { label, permission } = VERCEL_SOURCES[source];
    this.coverage.set(
      source,
      ok
        ? { key: source, label, permission, ok: true }
        : {
            key: source,
            label,
            permission,
            ok: false,
            status: (err as VercelError)?.status || 0,
            message: String((err as Error)?.message || err).slice(0, 200),
          },
    );
  }

  async #acquire(): Promise<void> {
    while (this.#inFlight >= MAX_IN_FLIGHT) await new Promise<void>((r) => this.#queue.push(r));
    this.#inFlight++;
    const until = pauses.get(this.#key) || 0;
    if (until > Date.now()) await sleep(until - Date.now());
  }

  #release(): void {
    this.#inFlight--;
    this.#queue.shift()?.();
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, Math.max(0, ms)));
