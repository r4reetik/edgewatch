// Small helpers shared by check modules.

import type { EngineOptions, Inventory, ZoneInventory } from "../types.ts";
import { DAY_MS } from "../../shared/time.ts";

export type Dash = ReturnType<typeof dash>;

/** Links into the Cloudflare dashboard for an account. */
export function dash(inv: Pick<Inventory, "accountId">) {
  const base = `https://dash.cloudflare.com/${inv.accountId}`;
  return {
    members: `${base}/members`,
    accountConfig: `${base}/configurations`,
    apiTokens: `${base}/api-tokens`,
    notifications: `${base}/notifications`,
    ipRules: `${base}/configurations/lists`,
    zone: (z: string, path = "") => `${base}/${z}${path ? "/" + path : ""}`,
    worker: (name: string) => `${base}/workers/services/view/${encodeURIComponent(name)}/production/settings`,
    pages: (name: string) => `${base}/pages/view/${encodeURIComponent(name)}/settings`,
    r2: (name: string) => `${base}/r2/default/buckets/${encodeURIComponent(name)}/settings`,
    zt: (path: string) => `https://one.dash.cloudflare.com/${inv.accountId}/${path}`,
  };
}

/** Email domains treated as internal: the entity's domains plus every zone in the account. */
export function orgDomains(inv: Inventory, opts: EngineOptions): Set<string> {
  return new Set([...opts.orgDomains.map((d) => d.trim().toLowerCase()).filter(Boolean), ...inv.zones.map((z) => z.name.toLowerCase())]);
}

export const emailDomain = (email: string): string =>
  String(email || "")
    .toLowerCase()
    .split("@")[1] || "";
export const uniq = <T>(a: T[]): T[] => [...new Set(a)];
export const proxiedZone = (z: ZoneInventory): boolean => z.dns.some((r) => r.proxied);
/** Whole days from now until `t` (negative when it's past). */
export const daysUntil = (t: number, now: number): number => Math.floor((t - now) / DAY_MS);
/** Whole days since `t`. */
export const daysSince = (t: number, now: number): number => Math.floor((now - t) / DAY_MS);
/** Cloudflare's dates come as ISO strings or "2026-06-10 00:00:00 +0000 UTC". */
export const parseDate = (s: string | null | undefined): number | null => {
  if (!s) return null;
  const t = Date.parse(
    String(s)
      .replace(" +0000 UTC", "Z")
      .replace(/^(\d{4}-\d\d-\d\d) /, "$1T"),
  );
  return Number.isFinite(t) ? t : null;
};

/** "24h", "30m", "168h" -> hours. */
export function durationHours(s: string | undefined): number | null {
  const m = String(s || "").match(/^(\d+(?:\.\d+)?)(h|m|s)$/);
  if (!m) return null;
  const n = Number(m[1]);
  return m[2] === "h" ? n : m[2] === "m" ? n / 60 : n / 3600;
}

/** The zone a hostname belongs to (longest match), if any. */
export const zoneOf = (zones: string[], h: string): string | null =>
  zones.filter((z) => h === z || h.endsWith(`.${z}`)).sort((a, b) => b.length - a.length)[0] ?? null;

/** Free webmail providers: an Access rule for a whole free-mail domain admits anyone. */
export const FREE_MAIL = new Set([
  "gmail.com",
  "googlemail.com",
  "outlook.com",
  "hotmail.com",
  "live.com",
  "yahoo.com",
  "icloud.com",
  "me.com",
  "aol.com",
  "proton.me",
  "protonmail.com",
  "gmx.com",
  "yandex.com",
  "mail.com",
  "zoho.com",
  "qq.com",
  "163.com",
]);
