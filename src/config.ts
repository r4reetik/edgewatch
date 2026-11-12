// API tokens live in <dataDir>/credentials.json (file mode 0600), keyed by a
// random token ID. The database only stores that ID, so a database copy never
// carries a token. One token can serve several accounts.

import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync, chmodSync, rmSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";

export type TokenKind = "user" | "account" | null;

export interface StoredToken {
  token: string;
  kind: TokenKind;
  addedAt: string;
}

export class TokenVault {
  readonly #path: string | null;
  #tokens: Record<string, StoredToken> = {};

  /** `dataDir` null keeps tokens in memory only (tests). */
  constructor(dataDir: string | null) {
    this.#path = dataDir ? join(dataDir, "credentials.json") : null;
    if (this.#path && existsSync(this.#path)) {
      try {
        this.#tokens = JSON.parse(readFileSync(this.#path, "utf8")).tokens || {};
      } catch {
        throw new Error(`Can't read ${this.#path}. Fix or remove it, then start Keelson again.`);
      }
    }
  }

  get(id: string): StoredToken | null {
    return this.#tokens[id] ?? null;
  }

  /** Stores a token and returns its ID; the same token value always gets the same ID. */
  put(token: string, kind: TokenKind): string {
    const existing = Object.entries(this.#tokens).find(([, t]) => t.token === token);
    if (existing) {
      if (kind && existing[1].kind !== kind) {
        existing[1].kind = kind;
        this.#write();
      }
      return existing[0];
    }
    const id = randomBytes(8).toString("hex");
    this.#tokens[id] = { token, kind, addedAt: new Date().toISOString() };
    this.#write();
    return id;
  }

  remove(id: string): void {
    if (!(id in this.#tokens)) return;
    delete this.#tokens[id];
    this.#write();
  }

  /** Drops tokens no account uses any more. */
  retain(used: Set<string>): void {
    const stale = Object.keys(this.#tokens).filter((id) => !used.has(id));
    if (!stale.length) return;
    for (const id of stale) delete this.#tokens[id];
    this.#write();
  }

  hint(id: string): string | null {
    const t = this.#tokens[id];
    return t ? maskToken(t.token) : null;
  }

  #write(): void {
    if (!this.#path) return;
    mkdirSync(join(this.#path, ".."), { recursive: true, mode: 0o700 });
    const tmp = `${this.#path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify({ tokens: this.#tokens }, null, 2), { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, this.#path);
  }
}

/** The single-account config.json written by Keelson 0.2 and earlier. */
export function readLegacyConfig(dataDir: string): { token: string; accountId: string; accountName: string | null; tokenKind: TokenKind } | null {
  const path = join(dataDir, "config.json");
  if (!existsSync(path)) return null;
  try {
    const c = JSON.parse(readFileSync(path, "utf8"));
    return c.token && c.accountId ? { token: c.token, accountId: c.accountId, accountName: c.accountName ?? null, tokenKind: c.tokenKind ?? null } : null;
  } catch {
    return null;
  }
}

export function removeLegacyConfig(dataDir: string): void {
  rmSync(join(dataDir, "config.json"), { force: true });
}

/** "…a1b2" — the only part of a token ever shown in the UI or logs. */
export const maskToken = (t: string): string => (t.length > 8 ? `…${t.slice(-4)}` : "…");
