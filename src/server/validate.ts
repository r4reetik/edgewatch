// Request parsing and validation. Every function either returns clean values or
// throws a 400 HttpError with a message fit to show the user.

import type { Context } from "hono";
import { badRequest } from "./errors.ts";
import { validWebhookUrl } from "../notify.ts";
import { isSeverity, SCORED_SEVERITIES } from "../shared/severity.ts";
import { TRIAGE_STATUSES, type TriageStatus } from "../shared/triage.ts";
import type { Entity, EntityUpdate, TriagePatch } from "../store/repo.ts";
import type { Settings } from "../shared/api.ts";
import { ACCOUNT_ID_PATTERN, isProvider, type ProviderId } from "../shared/providers.ts";

export const FINGERPRINT = /^[0-9a-f]{20}$/;
export const ACCOUNT_ID = ACCOUNT_ID_PATTERN.cloudflare;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const MAX_TOKEN = 200;
export const MAX_ACCOUNTS_PER_ADD = 50;
export const MAX_TRIAGE_BATCH = 5000;

// Body is Record<string, any> on purpose: every field is checked before use.
export type Body = Record<string, any>;

/** The JSON body, or null when it is missing or malformed. Hono caches it, so this can run twice. */
export async function readJson(c: Context): Promise<Body | null> {
  try {
    const b = await c.req.json();
    return b && typeof b === "object" && !Array.isArray(b) ? b : null;
  } catch {
    return null;
  }
}

export async function requireJson(c: Context): Promise<Body> {
  const b = await readJson(c);
  if (!b) throw badRequest("Invalid request");
  return b;
}

export function token(v: unknown): string {
  const t = String(v ?? "").trim();
  if (!t || t.length > MAX_TOKEN) throw badRequest("Enter an API token.");
  return t;
}

/** A display name: trimmed, one line, at most 80 characters. */
export function cleanName(v: unknown): string {
  return String(v ?? "")
    .replace(/[\u0000-\u001f\u007f]/g, "")
    .trim()
    .slice(0, 80);
}

export function requiredName(v: unknown, what = "entity"): string {
  const n = cleanName(v);
  if (!n) throw badRequest(`Give the ${what} a name.`);
  return n;
}

/** The provider a request is about. Requests from before providers existed are Cloudflare's. */
export function providerId(v: unknown): ProviderId {
  if (v == null || v === "") return "cloudflare";
  if (!isProvider(v)) throw badRequest("Unknown provider");
  return v;
}

export function accountIds(v: unknown, provider: ProviderId = "cloudflare"): string[] {
  if (v == null) return [];
  if (!Array.isArray(v)) throw badRequest("accountIds must be a list");
  // Cloudflare IDs are hex and compared lowercase; Vercel IDs are case-sensitive.
  const ids = [...new Set(v.map((x) => (provider === "cloudflare" ? String(x).trim().toLowerCase() : String(x).trim())))];
  if (ids.some((id) => !ACCOUNT_ID_PATTERN[provider].test(id)))
    throw badRequest(provider === "cloudflare" ? "An account ID is 32 hexadecimal characters." : "That isn't a Vercel team or account ID.");
  if (ids.length > MAX_ACCOUNTS_PER_ADD) throw badRequest(`Add at most ${MAX_ACCOUNTS_PER_ADD} accounts at a time.`);
  return ids;
}

export function fingerprints(v: unknown): string[] {
  const fps = Array.isArray(v) ? v.map(String) : [];
  if (!fps.length || fps.length > MAX_TRIAGE_BATCH || fps.some((f) => !FINGERPRINT.test(f))) throw badRequest("Invalid findings");
  return fps;
}

export const direction = (v: unknown): "up" | "down" => {
  if (v !== "up" && v !== "down") throw badRequest("move must be up or down");
  return v;
};

export function bool(v: unknown, name: string): boolean {
  if (typeof v !== "boolean") throw badRequest(`${name} must be true or false`);
  return v;
}

/**
 * A triage change. Fields that are absent stay as they are; null or "" clears
 * them. `appendNote` adds to the note instead of replacing it (bulk triage).
 */
export function triagePatch(b: Body): { patch: TriagePatch; appendNote?: string } {
  const text = (v: unknown, n: number) => (v == null || v === "" ? null : String(v).trim().slice(0, n) || null);
  const date = (v: unknown) => {
    const d = text(v, 10);
    if (d && !DATE.test(d)) throw badRequest("Dates must be YYYY-MM-DD");
    return d;
  };
  const patch: TriagePatch = {};
  if (b.status !== undefined) {
    if (!TRIAGE_STATUSES.includes(b.status)) throw badRequest("Invalid status");
    patch.status = b.status as TriageStatus;
  }
  if (b.owner !== undefined) patch.owner = text(b.owner, 120);
  if (b.note !== undefined) patch.note = text(b.note, 4000);
  if (b.dueDate !== undefined) patch.dueDate = date(b.dueDate);
  if (b.acceptUntil !== undefined) patch.acceptUntil = date(b.acceptUntil);
  const appendNote = text(b.appendNote, 4000) || undefined;
  if (!Object.keys(patch).length && !appendNote) throw badRequest("Nothing to change");
  return { patch, appendNote };
}

/** Applies a partial entity update; webhook URLs are kept when omitted and cleared with "". */
export function mergeEntity(cur: Entity, b: Body): EntityUpdate {
  const next: EntityUpdate = { name: cur.name, includeInAll: cur.includeInAll, orgDomains: [...cur.orgDomains], notifications: { ...cur.notifications } };
  if (b.name !== undefined) next.name = requiredName(b.name);
  if (b.includeInAll !== undefined) next.includeInAll = bool(b.includeInAll, "includeInAll");
  if (b.orgDomains !== undefined) {
    if (!Array.isArray(b.orgDomains)) throw badRequest("orgDomains must be a list");
    const doms = b.orgDomains.map((d: unknown) => String(d).trim().toLowerCase()).filter(Boolean);
    if (doms.some((d: string) => !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(d))) throw badRequest("Each company domain must look like example.com");
    next.orgDomains = [...new Set<string>(doms)].slice(0, 50);
  }
  if (b.notifications) {
    const n = b.notifications;
    for (const k of ["slackWebhookUrl", "webhookUrl"] as const) {
      if (n[k] === undefined) continue;
      const u = String(n[k]).trim();
      if (!validWebhookUrl(u)) throw badRequest("Webhook URLs must start with https://");
      next.notifications[k] = u;
    }
    if (n.minSeverity !== undefined) {
      if (!(SCORED_SEVERITIES as readonly string[]).includes(n.minSeverity)) throw badRequest("Invalid minimum severity");
      next.notifications.minSeverity = n.minSeverity;
    }
  }
  return next;
}

/** Applies a partial settings update. */
export function mergeSettings(cur: Settings, b: Body): Settings {
  const next: Settings = structuredClone(cur);
  const int = (v: unknown, min: number, max: number, msg: string) => {
    const n = Number(v);
    if (!Number.isInteger(n) || n < min || n > max) throw badRequest(msg);
    return n;
  };
  if (b.schedule) {
    next.schedule = {
      enabled: b.schedule.enabled === undefined ? cur.schedule.enabled : !!b.schedule.enabled,
      hourUtc: b.schedule.hourUtc === undefined ? cur.schedule.hourUtc : int(b.schedule.hourUtc, 0, 23, "Schedule time is invalid"),
      minuteUtc: b.schedule.minuteUtc === undefined ? cur.schedule.minuteUtc : int(b.schedule.minuteUtc, 0, 59, "Schedule time is invalid"),
    };
  }
  if (b.retentionDays !== undefined) next.retentionDays = int(b.retentionDays, 7, 3650, "Retention must be between 7 and 3650 days");
  if (b.slaDays) {
    for (const k of SCORED_SEVERITIES) {
      if (b.slaDays[k] !== undefined) next.slaDays[k] = int(b.slaDays[k], 1, 3650, "SLA days must be between 1 and 3650");
    }
  }
  if (b.updates !== undefined) next.updates = { check: bool(b.updates?.check, "updates.check") };
  if (b.probes !== undefined) next.probes = { takeover: bool(b.probes?.takeover, "probes.takeover") };
  if (b.baseUrl !== undefined) {
    const u = String(b.baseUrl).trim().replace(/\/$/, "");
    if (u && !/^https?:\/\/[^\s/]+/.test(u)) throw badRequest("Link URL must start with http:// or https://");
    next.baseUrl = u;
  }
  return next;
}

export function severityOrNull(v: unknown) {
  if (v == null) return null;
  if (!isSeverity(v)) throw badRequest("Invalid severity");
  return v;
}

/** A path parameter (always present when the route matched). */
export function param(c: Context, name: string): string {
  const v = c.req.param(name);
  if (v == null) throw badRequest(`Missing ${name}`);
  return v;
}
