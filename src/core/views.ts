// Snapshot views stored with each scan: the zones grid, value/utilization, and
// recent audit-log activity. Pure functions of the inventory.

import { proxiedZone } from "./checks/helpers.ts";
import { RULESET } from "./cf-constants.ts";
import { countBySeverity } from "../shared/severity.ts";
import type { Api, Inventory, Result } from "./types.ts";
import type { ActivityEvent, ActivityView, Subscription, ValueView, ValueZone, ZoneRow } from "../shared/api.ts";
import { DAY_MS } from "../shared/time.ts";

const CF_MANAGED = RULESET.cloudflareManaged;
const OWASP = RULESET.owasp;

const managedIds = (z: Inventory["zones"][number]): string[] =>
  (z.wafManaged?.rules || []).filter((r) => r.enabled !== false).map((r) => r.action_parameters?.id);
const botOn = (z: Inventory["zones"][number]): boolean | null =>
  z.bot ? (z.plan === "free" ? !!z.bot.fight_mode : ["block", "managed_challenge"].includes(z.bot.sbfm_definitely_automated)) : null;

export function zoneGrid(inv: Inventory, failures: Result[]): ZoneRow[] {
  return inv.zones.map((z): ZoneRow => {
    const s = z.settings || {};
    const managed = managedIds(z);
    return {
      name: z.name,
      plan: z.plan,
      planName: z.planName,
      status: z.status,
      paused: z.paused,
      proxiedZone: proxiedZone(z),
      records: z.dns.length,
      proxied: z.dns.filter((r) => r.proxied).length,
      ssl: s.ssl ?? null,
      minTls: s.min_tls_version ?? null,
      alwaysHttps: s.always_use_https ?? null,
      hsts: s.security_header ? !!s.security_header.strict_transport_security?.enabled : null,
      tls13: s.tls_1_3 ?? null,
      dnssec: z.dnssec?.status ?? null,
      wafManaged: z.plan === "free" ? "n/a" : z.wafManaged === undefined ? null : managed.includes(CF_MANAGED),
      owasp: z.plan === "free" ? "n/a" : z.wafManaged === undefined ? null : managed.includes(OWASP),
      rateLimitRules: z.rateLimit === undefined ? null : (z.rateLimit?.rules || []).length,
      botProtection: botOn(z),
      aiBots: z.bot?.ai_bots_protection ?? null,
      securityLevel: s.security_level ?? null,
      pageShield: z.pageShield ? !!z.pageShield.enabled : null,
      leakedCredentials: z.leaked ? !!z.leaked.enabled : null,
      caa: z.dnsReadable ? z.dns.some((r) => r.type === "CAA") : null,
      traffic: inv.traffic[z.id] || null,
      findings: countBySeverity(failures.filter((f) => f.zone === z.name)),
    };
  });
}

export function valueView(inv: Inventory): ValueView {
  const subs = (inv.subscriptions || []).map(
    (s: Api): Subscription => ({
      name: s.rate_plan?.public_name || s.product?.public_name || s.rate_plan?.id || "Subscription",
      scope: s.rate_plan?.scope || (s.zone ? "zone" : "account"),
      zone: s.zone?.name || null,
      price: Number(s.price) || 0,
      currency: s.currency || "USD",
      frequency: s.frequency || "",
      state: s.state || "",
    }),
  );
  const monthly = subs.reduce(
    (sum: number, s: { frequency: string; price: number }) =>
      sum + (s.frequency === "yearly" ? s.price / 12 : s.frequency === "monthly" ? s.price : s.frequency === "quarterly" ? s.price / 3 : 0),
    0,
  );

  const zones = inv.zones.map((z): ValueZone => {
    const s = z.settings || {};
    const managed = managedIds(z);
    // Edge features can't apply to a zone that proxies nothing.
    const edge = <T>(v: T): T | null => (proxiedZone(z) ? v : null);
    const t = inv.traffic[z.id];
    return {
      name: z.name,
      plan: z.planName,
      paid: z.plan !== "free",
      price: z.planPrice,
      requests: t?.requests ?? null,
      threats: t?.threats ?? null,
      cached: t ? t.cachedRequests / Math.max(1, t.requests) : null,
      features: {
        "Managed WAF": edge(z.plan === "free" || z.wafManaged === undefined ? null : managed.includes(CF_MANAGED)),
        "OWASP ruleset": edge(z.plan === "free" || z.wafManaged === undefined ? null : managed.includes(OWASP)),
        "Rate limiting": edge(z.rateLimit === undefined ? null : (z.rateLimit?.rules || []).length > 0),
        "Bot protection": edge(botOn(z)),
        "Image optimization (Polish)": edge(z.plan === "free" || !z.settings ? null : !!s.polish && s.polish !== "off"),
        "Page Shield": edge(z.pageShield ? !!z.pageShield.enabled : null),
        "Leaked credentials": edge(z.leaked ? !!z.leaked.enabled : null),
        DNSSEC: z.dnssec ? z.dnssec.status === "active" : null,
        "HTTP/3": edge(s.http3 ? s.http3 === "on" : null),
      },
    };
  });
  const traffic = Object.values(inv.traffic);
  return {
    subscriptions: subs,
    monthly: Math.round(monthly * 100) / 100,
    zones,
    counts: {
      zones: inv.zones.length,
      paidZones: inv.zones.filter((z) => z.plan !== "free").length,
      members: inv.members?.length ?? null,
      accessApps: inv.accessApps?.length ?? null,
      serviceTokens: inv.serviceTokens?.length ?? null,
      tunnels: inv.tunnels?.length ?? null,
      healthyTunnels: (inv.tunnels || []).filter((t: Api) => t.status === "healthy").length,
      workers: inv.workers.length,
      r2Buckets: inv.r2.length,
      ztDevices: inv.devices?.length ?? null,
      gatewayRules: inv.gatewayRules?.length ?? null,
      notifications: inv.alertPolicies?.filter((p: Api) => p.enabled).length ?? null,
      requests30d: traffic.reduce((s, t) => s + t.requests, 0),
      cachedRequests30d: traffic.reduce((s, t) => s + t.cachedRequests, 0),
      threats30d: traffic.reduce((s, t) => s + t.threats, 0),
    },
  };
}

const ACTIVITY_CATEGORIES: [string, RegExp][] = [
  ["Access & identity", /member|role|token|user|login|2fa|two_factor|sso|invite|api_key/i],
  ["Zero Trust", /access|tunnel|gateway|cfd|warp|device/i],
  ["Security rules", /ruleset|firewall|waf|rate|rule|bot|security/i],
  ["DNS", /^rec_|dns|dnssec/i],
  ["Workers & code", /script|worker|pages|deploy|r2|d1|kv/i],
  ["Zone & TLS settings", /setting|zone|ssl|cert|tls|purge|cache/i],
];
const ROUTINE = /^(login|logout)$/i;

export function activityView(inv: Inventory): ActivityView {
  const events = (inv.audit || []).map((a: Api): ActivityEvent => {
    const type = String(a.action?.type || "");
    const hay = `${type} ${a.resource?.type || ""}`;
    const category = (ACTIVITY_CATEGORIES.find(([, re]) => re.test(hay)) || ["Other"])[0];
    return {
      when: a.when,
      actor: a.actor?.email || a.actor?.type || "unknown",
      actorType: a.actor?.type || null,
      ip: a.actor?.ip || null,
      type,
      info: String(a.action?.info || ""),
      ok: a.action?.result !== false,
      resource: [a.resource?.type, a.resource?.id].filter(Boolean).join(": ").slice(0, 120),
      zone: a.metadata?.zone_name || a.metadata?.zone?.name || null,
      category,
      routine: ROUTINE.test(type),
      destructive: /del|remove|revoke|purge|disable/i.test(type),
    };
  });
  const byCategory: Record<string, number> = {},
    byActor: Record<string, number> = {};
  for (const e of events) {
    if (e.routine) continue;
    byCategory[e.category] = (byCategory[e.category] || 0) + 1;
    byActor[e.actor] = (byActor[e.actor] || 0) + 1;
  }
  return {
    available: inv.audit != null,
    since: new Date(inv.now - 7 * DAY_MS).toISOString(),
    total: events.length,
    byCategory,
    byActor,
    events: events.slice(0, 500),
  };
}
