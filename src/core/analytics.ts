// GraphQL Analytics reads: traffic totals, DNS lookups per hostname, and the
// security signals the traffic checks correlate with configuration. All
// queries are read-only (GraphQL is POST-only by Cloudflare's design).
//
// Which fields a zone can query depends on its plan, and one forbidden field
// fails a whole query. So zones are batched by plan (10 per query, Cloudflare's
// limit), every dataset the plan supports is aliased into one query, and when
// that fails the parts are retried one by one: parts the plan doesn't allow are
// recorded as unavailable rather than as a permission problem.

import type { CloudflareClient } from "./cloudflare.ts";
import { isHostRecord } from "./dns-util.ts";
import { DAY_MS, HOUR_MS, isoSeconds } from "../shared/time.ts";
import type { AccessLoginStats, Api, Inventory, ZoneAnalytics, ZoneInventory } from "./types.ts";

/** How far back the security signals look. */
export const WINDOW_DAYS = 7;
/** Per-name DNS analytics fallback is capped so huge zones stay within API budgets. */
const MAX_LOOKUP_NAMES = 2000;
const ZONES_PER_QUERY = 10;

/** Paths that hold secrets or debug data. A 200 with a non-HTML body is worth a look. */
export const SENSITIVE_PATHS = [
  "%/.env%",
  "%/.git/%",
  "%/.svn/%",
  "%/.aws/%",
  "%/.ssh/%",
  "%/actuator%",
  "%/server-status%",
  "%phpinfo%",
  "%/.htpasswd%",
  "%/.DS_Store%",
  "%/wp-config.php%",
  "%/.npmrc%",
  "%/.docker/config.json%",
  "%/id_rsa%",
];
/**
 * Response types a leaked file or debug page can have. HTML is usually a
 * single-page app's catch-all page, and CSS, script or image bodies can't be
 * the file asked for, so those don't count.
 */
export const LEAK_CONTENT = new Set(["txt", "text", "plain", "json", "octet-stream", "xml", "yaml", "x-yaml", "x-sh", "csv", "zip", "gzip", "unknown"]);
const LEAKED_RESULTS = ["password_leaked", "username_and_password_leaked", "username_password_similar", "username_leaked"];
const LOGIN_PATHS = ["%login%", "%signin%", "%sign-in%", "%/auth%", "%/session%", "%/token%", "%/oauth%"];
/** Actions that mean a request was stopped or challenged. */
const STOPPED = ["block", "challenge", "managed_challenge", "jschallenge", "js_challenge", "connection_close"];

type Tier = "free" | "pro" | "business" | "enterprise";
const TIER_RANK: Record<Tier, number> = { free: 0, pro: 1, business: 2, enterprise: 3 };
const tierOf = (plan: string): Tier => (plan in TIER_RANK ? (plan as Tier) : "free");

interface Part {
  key: keyof ZoneAnalytics;
  /** Lowest plan that can query it. */
  min: Tier;
  /** The aliased dataset selection, with $from/$to (and $since for longer windows). */
  query: string;
  /** Data source of the part, for coverage. */
  source?: "securityAnalytics" | "dmarcReports" | "logpushHealth";
  read: (rows: Api[]) => unknown;
}

const sumBy = <T extends Record<string, unknown>>(rows: Api[], key: (d: Api) => string, make: (d: Api) => T) => {
  const m = new Map<string, T & { count: number }>();
  for (const r of rows) {
    const k = key(r.dimensions || {});
    const cur = m.get(k) || { ...make(r.dimensions || {}), count: 0 };
    cur.count += Number(r.count || 0);
    m.set(k, cur);
  }
  return [...m.values()].sort((a, b) => b.count - a.count);
};

const or = (field: string, patterns: string[]) => `OR:[${patterns.map((p) => `{${field}:${JSON.stringify(p)}}`).join(",")}]`;
const http = (alias: string, filter: string, dims: string, limit = 200) =>
  `${alias}:httpRequestsAdaptiveGroups(limit:${limit},filter:{datetime_geq:$from,datetime_lt:$to,${filter}},orderBy:[count_DESC]){count dimensions{${dims}}}`;

const PARTS: Part[] = [
  {
    key: "sensitive",
    min: "free",
    query: http(
      "sensitive",
      `edgeResponseStatus:200,${or("clientRequestPath_like", SENSITIVE_PATHS)}`,
      "clientRequestHTTPHost clientRequestPath edgeResponseContentTypeName",
      100,
    ),
    read: (rows) =>
      sumBy(
        rows,
        (d) => `${d.clientRequestHTTPHost}|${d.clientRequestPath}|${d.edgeResponseContentTypeName}`,
        (d) => ({ host: String(d.clientRequestHTTPHost), path: String(d.clientRequestPath), contentType: String(d.edgeResponseContentTypeName || "") }),
      ),
  },
  {
    key: "logOnly",
    min: "free",
    query: http("logOnly", `securityAction:"log"`, "securitySource", 20),
    read: (rows) =>
      sumBy(
        rows,
        (d) => String(d.securitySource),
        (d) => ({ source: String(d.securitySource) }),
      ),
  },
  {
    key: "hosts",
    min: "free",
    query: http("hosts", 'requestSource:"eyeball"', "clientRequestHTTPHost", 200),
    read: (rows) => rows.map((r) => ({ host: String(r.dimensions.clientRequestHTTPHost).toLowerCase(), count: Number(r.count) })),
  },
  {
    key: "oldTls",
    min: "free",
    query: http("oldTls", `clientSSLProtocol_in:["TLSv1","TLSv1.1"]`, "clientRequestHTTPHost clientSSLProtocol", 50),
    read: (rows) =>
      sumBy(
        rows,
        (d) => `${d.clientRequestHTTPHost}|${d.clientSSLProtocol}`,
        (d) => ({ host: String(d.clientRequestHTTPHost), protocol: String(d.clientSSLProtocol) }),
      ),
  },
  {
    key: "leakedLogins",
    min: "free",
    // Permanent redirects (host or HTTPS canonicalization) never reached the login handler.
    query: http(
      "leakedLogins",
      `leakedCredentialCheckResult_in:${JSON.stringify(LEAKED_RESULTS)},clientRequestHTTPMethodName:"POST",edgeResponseStatus_lt:400,edgeResponseStatus_notin:[301,308]`,
      "clientRequestHTTPHost clientRequestPath leakedCredentialCheckResult edgeResponseStatus",
      50,
    ),
    read: (rows) =>
      sumBy(
        rows,
        (d) => `${d.clientRequestHTTPHost}|${d.clientRequestPath}|${d.leakedCredentialCheckResult}|${d.edgeResponseStatus}`,
        (d) => ({
          host: String(d.clientRequestHTTPHost),
          path: String(d.clientRequestPath),
          result: String(d.leakedCredentialCheckResult),
          status: Number(d.edgeResponseStatus),
        }),
      ),
  },
  {
    key: "plainHttp",
    min: "pro",
    query: http(
      "plainHttp",
      `clientRequestScheme:"http",edgeResponseStatus_geq:200,edgeResponseStatus_lt:300,requestSource:"eyeball"`,
      "clientRequestHTTPHost",
      50,
    ),
    read: (rows) => rows.map((r) => ({ host: String(r.dimensions.clientRequestHTTPHost), count: Number(r.count) })),
  },
  {
    key: "attacksPassed",
    min: "business",
    query: http(
      "attacksPassed",
      `wafAttackScoreClass:"attack",securityAction_notin:${JSON.stringify(STOPPED)},edgeResponseStatus_lt:400`,
      "clientRequestHTTPHost clientRequestPath",
      50,
    ),
    read: (rows) =>
      sumBy(
        rows,
        (d) => `${d.clientRequestHTTPHost}|${d.clientRequestPath}`,
        (d) => ({ host: String(d.clientRequestHTTPHost), path: String(d.clientRequestPath) }),
      ),
  },
  {
    key: "botsPassed",
    min: "enterprise",
    query: http(
      "botsPassed",
      `botScore_geq:1,botScore_leq:29,verifiedBotCategory:"",clientRequestHTTPMethodName:"POST",edgeResponseStatus_lt:400,${or("clientRequestPath_like", LOGIN_PATHS)}`,
      "clientRequestHTTPHost clientRequestPath",
      50,
    ),
    read: (rows) =>
      sumBy(
        rows,
        (d) => `${d.clientRequestHTTPHost}|${d.clientRequestPath}`,
        (d) => ({ host: String(d.clientRequestHTTPHost), path: String(d.clientRequestPath) }),
      ),
  },
  {
    // 30 days of rule hits, to find rules that never match. Only plans that keep a 30-day window.
    key: "ruleHits",
    min: "enterprise",
    query: "ruleHits:firewallEventsAdaptiveGroups(limit:10000,filter:{datetime_geq:$since,datetime_lt:$to}){count dimensions{ruleId}}",
    read: (rows) => Object.fromEntries(rows.map((r) => [String(r.dimensions.ruleId), Number(r.count)])),
  },
  {
    key: "logpushFailures",
    min: "free",
    source: "logpushHealth",
    query:
      "logpushFailures:logpushHealthAdaptiveGroups(limit:100,filter:{datetime_geq:$day,datetime_lt:$to,success:0},orderBy:[count_DESC]){count dimensions{jobId error}}",
    read: (rows) => rows.map((r) => ({ jobId: String(r.dimensions.jobId), error: String(r.dimensions.error || ""), count: Number(r.count) })),
  },
  {
    key: "dmarcSources",
    min: "free",
    source: "dmarcReports",
    query:
      "dmarcSources:dmarcReportsSourcesAdaptiveGroups(limit:200,filter:{date_geq:$fromDate,date_lt:$toDate},orderBy:[sum_totalMatchingMessages_DESC]){sum{totalMatchingMessages dmarc} dimensions{headerFrom sourceOrgName}}",
    read: (rows) =>
      rows.map((r) => ({
        from: String(r.dimensions.headerFrom),
        org: String(r.dimensions.sourceOrgName || "unknown"),
        total: Number(r.sum?.totalMatchingMessages || 0),
        passing: Number(r.sum?.dmarc || 0),
      })),
  },
];

const VAR_TYPES = { from: "Time!", to: "Time!", since: "Time!", day: "Time!", fromDate: "Date!", toDate: "Date!" } as const;

const ACCESS_DENIED = /does not have access to the field|not authorized for that|you don't have access|not available on/i;

/**
 * Security signals for every zone, attached as `zone.analytics`. Zones with no
 * proxied records get none: their traffic doesn't pass through Cloudflare.
 */
export async function zoneAnalytics(cf: CloudflareClient, zones: ZoneInventory[], now: number): Promise<void> {
  const vars = {
    from: isoSeconds(now - WINDOW_DAYS * DAY_MS),
    to: isoSeconds(now),
    since: isoSeconds(now - 30 * DAY_MS + HOUR_MS),
    day: isoSeconds(now - DAY_MS),
    fromDate: isoSeconds(now - WINDOW_DAYS * DAY_MS).slice(0, 10),
    toDate: isoSeconds(now).slice(0, 10),
  };
  const proxied = zones.filter((z) => z.dns.some((r) => r.proxied));
  const byTier = new Map<Tier, ZoneInventory[]>();
  for (const z of proxied) byTier.set(tierOf(z.plan), [...(byTier.get(tierOf(z.plan)) || []), z]);

  let failed: unknown = null,
    ok = false;
  for (const [tier, list] of byTier) {
    const parts = PARTS.filter((p) => TIER_RANK[tier] >= TIER_RANK[p.min]);
    for (let i = 0; i < list.length; i += ZONES_PER_QUERY) {
      const batch = list.slice(i, i + ZONES_PER_QUERY);
      const results = new Map<string, Record<string, Api[] | null>>(batch.map((z) => [z.id, {}]));
      const unavailable: string[] = [];
      const run = async (ps: Part[]) => {
        const body = ps.map((p) => p.query).join("\n");
        // GraphQL rejects declared variables a query doesn't use, so declare only those in these parts.
        const used = (Object.keys(VAR_TYPES) as (keyof typeof VAR_TYPES)[]).filter((k) => body.includes(`$${k}`));
        const q = `query($tags:[String!]${used.map((k) => `,$${k}:${VAR_TYPES[k]}`).join("")}){viewer{zones(filter:{zoneTag_in:$tags}){zoneTag ${body}}}}`;
        const d = await cf.graphql(q, { tags: batch.map((z) => z.id), ...Object.fromEntries(used.map((k) => [k, vars[k]])) });
        for (const zr of d.viewer.zones as Api[]) for (const p of ps) results.get(zr.zoneTag)![p.key] = zr[p.key] ?? [];
      };
      try {
        await run(parts);
        ok = true;
      } catch {
        // Retry part by part: keep what the plan allows, mark the rest unavailable.
        for (const p of parts) {
          try {
            await run([p]);
            ok = true;
          } catch (e) {
            if (ACCESS_DENIED.test(String((e as Error).message))) unavailable.push(p.key);
            else failed ||= e;
            for (const z of batch) results.get(z.id)![p.key] = null;
          }
        }
      }
      for (const z of batch) {
        const r = results.get(z.id)!;
        const value = (k: keyof ZoneAnalytics) => {
          const p = PARTS.find((x) => x.key === k)!;
          return TIER_RANK[tier] < TIER_RANK[p.min] || r[k] == null ? null : p.read(r[k]!);
        };
        z.analytics = {
          from: vars.from,
          to: vars.to,
          days: WINDOW_DAYS,
          unavailable: [...unavailable, ...PARTS.filter((p) => TIER_RANK[tier] < TIER_RANK[p.min]).map((p) => p.key)],
          sensitive: value("sensitive") as ZoneAnalytics["sensitive"],
          logOnly: value("logOnly") as ZoneAnalytics["logOnly"],
          hosts: value("hosts") as ZoneAnalytics["hosts"],
          oldTls: value("oldTls") as ZoneAnalytics["oldTls"],
          leakedLogins: value("leakedLogins") as ZoneAnalytics["leakedLogins"],
          plainHttp: value("plainHttp") as ZoneAnalytics["plainHttp"],
          attacksPassed: value("attacksPassed") as ZoneAnalytics["attacksPassed"],
          botsPassed: value("botsPassed") as ZoneAnalytics["botsPassed"],
          ruleHits: value("ruleHits") as ZoneAnalytics["ruleHits"],
          ruleHitsDays: value("ruleHits") ? 30 : null,
          logpushFailures: value("logpushFailures") as ZoneAnalytics["logpushFailures"],
          dmarcSources: value("dmarcSources") as ZoneAnalytics["dmarcSources"],
        };
      }
    }
  }
  if (!proxied.length) return;
  if (ok && !failed) cf.note("securityAnalytics", true);
  else if (failed) cf.note("securityAnalytics", false, failed);
}

/** 30 days of zone-level HTTP totals, batched per GraphQL call. */
export async function trafficTotals(cf: CloudflareClient, zoneTags: string[], now: number): Promise<Inventory["traffic"]> {
  const out: Inventory["traffic"] = {};
  const q = `query($tags:[String!],$from:Date!,$to:Date!){viewer{zones(filter:{zoneTag_in:$tags}){zoneTag
    httpRequests1dGroups(limit:40,filter:{date_geq:$from,date_lt:$to}){sum{requests cachedRequests threats bytes}}}}}`;
  // One failing batch is recorded, and the other batches still count.
  for (let i = 0; i < zoneTags.length; i += ZONES_PER_QUERY) {
    try {
      const tags = zoneTags.slice(i, i + ZONES_PER_QUERY);
      const d = await cf.graphql(q, { tags, from: isoSeconds(now - 30 * DAY_MS).slice(0, 10), to: isoSeconds(now).slice(0, 10) });
      for (const z of d.viewer.zones as Api[]) {
        const t = { requests: 0, cachedRequests: 0, threats: 0, bytes: 0 };
        for (const g of z.httpRequests1dGroups) for (const k of Object.keys(t) as (keyof typeof t)[]) t[k] += g.sum[k] || 0;
        out[z.zoneTag] = t;
      }
      cf.note("traffic", true);
    } catch (e) {
      cf.note("traffic", false, e);
    }
  }
  return out;
}

/** Sampled DNS query counts per hostname over 30 days (null if analytics unreadable). */
export async function dnsLookups(cf: CloudflareClient, zone: ZoneInventory, now: number): Promise<Record<string, number> | null> {
  const names = [...new Set(zone.dns.filter(isHostRecord).map((r) => String(r.name).toLowerCase()))];
  if (!names.length) return {};
  const from = isoSeconds(now - 30 * DAY_MS + HOUR_MS),
    to = isoSeconds(now);
  const counts: Record<string, number> = Object.fromEntries(names.map((n) => [n, 0]));
  try {
    // One grouped query usually covers a zone; fall back to per-name queries when it's truncated.
    const q = `query($z:String!,$a:Time!,$b:Time!){viewer{zones(filter:{zoneTag:$z}){
      dnsAnalyticsAdaptiveGroups(limit:10000,filter:{datetime_geq:$a,datetime_lt:$b},orderBy:[count_DESC]){count dimensions{queryName}}}}}`;
    const d = await cf.graphql(q, { z: zone.id, a: from, b: to });
    const rows: Api[] = d.viewer.zones[0]?.dnsAnalyticsAdaptiveGroups || [];
    if (rows.length < 10000) {
      for (const r of rows) {
        const n = String(r.dimensions.queryName).toLowerCase().replace(/\.$/, "");
        if (n in counts) counts[n] += r.count;
      }
    } else {
      if (names.length > MAX_LOOKUP_NAMES) {
        cf.note(
          "dnsAnalytics",
          false,
          new Error(`${zone.name} has ${names.length} hostnames; stale-record detection is limited to zones under ${MAX_LOOKUP_NAMES}.`),
        );
        return null;
      }
      for (let i = 0; i < names.length; i += 25) {
        const batch = names.slice(i, i + 25);
        const parts = batch.map(
          (n, j) => `n${j}:dnsAnalyticsAdaptiveGroups(limit:1,filter:{datetime_geq:"${from}",datetime_lt:"${to}",queryName:${JSON.stringify(n)}}){count}`,
        );
        const d2 = await cf.graphql(`query($z:String!){viewer{zones(filter:{zoneTag:$z}){${parts.join("\n")}}}}`, { z: zone.id });
        const zz = d2.viewer.zones[0];
        batch.forEach((n, j) => {
          counts[n] = (zz[`n${j}`] as Api[]).reduce((s, x) => s + x.count, 0);
        });
      }
    }
    cf.note("dnsAnalytics", true);
    return counts;
  } catch (e) {
    cf.note("dnsAnalytics", false, e);
    return null;
  }
}

/** Access logins per application over the window: successes, failures and where they came from. */
export async function accessLogins(cf: CloudflareClient, now: number, hasApps: boolean): Promise<AccessLoginStats[] | null> {
  if (!hasApps) return [];
  const q = `query($acc:String!,$from:Time!,$to:Time!){viewer{accounts(filter:{accountTag:$acc}){
    accessLoginRequestsAdaptiveGroups(limit:10000,filter:{datetime_geq:$from,datetime_lt:$to}){count dimensions{appId isSuccessfulLogin country identityProvider}}}}}`;
  try {
    const d = await cf.graphql(q, { acc: cf.accountId, from: isoSeconds(now - WINDOW_DAYS * DAY_MS), to: isoSeconds(now) });
    const by = new Map<string, AccessLoginStats>();
    for (const r of (d.viewer.accounts[0]?.accessLoginRequestsAdaptiveGroups || []) as Api[]) {
      const id = String(r.dimensions.appId || "");
      const s = by.get(id) || { appId: id, success: 0, failed: 0, countries: [], idps: [] };
      if (r.dimensions.isSuccessfulLogin) {
        s.success += r.count;
        if (r.dimensions.country && !s.countries.includes(r.dimensions.country)) s.countries.push(r.dimensions.country);
      } else s.failed += r.count;
      if (r.dimensions.identityProvider && !s.idps.includes(r.dimensions.identityProvider)) s.idps.push(r.dimensions.identityProvider);
      by.set(id, s);
    }
    cf.note("accessLogins", true);
    return [...by.values()];
  } catch (e) {
    cf.note("accessLogins", false, e);
    return null;
  }
}
