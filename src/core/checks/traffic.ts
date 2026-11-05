// Traffic: what the last week of requests shows, read from GraphQL analytics
// and checked against configuration. Every finding here is "likely": analytics
// are sampled, and traffic changes from week to week.

import { defineChecks } from "./define.ts";
import { LEAK_CONTENT, WINDOW_DAYS } from "../analytics.ts";
import { RULESET } from "../cf-constants.ts";
import { groupBy } from "../../shared/collections.ts";
import type { Rule } from "../cf-types.ts";
import type { ZoneInventory } from "../types.ts";

const DOCS = "https://developers.cloudflare.com";
/** Spring Boot endpoints that are commonly public and harmless. */
const BENIGN_SENSITIVE = /\/actuator\/(health|info)(\/|$)|\/actuator\/?$/i;
const ATTACKS_HIGH = 100;
const ATTACKS_MIN = 10;
const PLAIN_HTTP_MIN = 100;
const OLD_TLS_MIN = 10;
const BOTS_MIN = 100;
/** Requests for a hostname with no DNS record before it's worth a look (scanners spoof Host headers). */
const UNKNOWN_HOST_MIN = 1000;

const fmt = (n: number) => n.toLocaleString("en-US");
const top = <T>(rows: T[], n: number, show: (r: T) => string) =>
  rows.slice(0, n).map(show).join("; ") + (rows.length > n ? `; and ${rows.length - n} more` : "");

/** Managed rulesets overridden to log only (the whole ruleset, a category or rules). */
function logOverrides(z: ZoneInventory): string[] {
  const out: string[] = [];
  for (const r of z.wafManaged?.rules || []) {
    if (r.action !== "execute" || r.enabled === false) continue;
    const o = r.action_parameters?.overrides || {};
    if (o.action === "log") out.push("every rule is set to log only");
    for (const c of o.categories || []) if (c.action === "log") out.push(`category "${c.category}" logs only`);
    const n = (o.rules || []).filter((x: { action?: string }) => x.action === "log").length;
    if (n) out.push(`${n} rule${n === 1 ? "" : "s"} set to log only`);
  }
  return out;
}

const usesCredentialCheck = (rules: Rule[] | undefined) =>
  (rules || []).some((r) => r.enabled !== false && /cf\.waf\.credential_check/.test(String(r.expression || "")));

export default defineChecks(
  {
    "TRF-001": {
      category: "Traffic",
      severity: "high",
      docs: `${DOCS}/waf/managed-rules/deploy-zone-dashboard/`,
      requires: ["wafRulesets", "securityAnalytics"],
      attackPath: true,
      title: "Managed rules are catching attacks but only logging them",
      why: "The WAF recognises these requests as attacks and lets every one through, because the managed rules are overridden to log only.",
      fix: "1. Review the logged matches under Security → Events (filter Action: Log). 2. Add exceptions for the false positives. 3. Remove the log-only override so the rules block.",
    },
    "TRF-002": {
      category: "Traffic",
      severity: "high",
      docs: `${DOCS}/waf/detections/attack-score/`,
      requires: ["securityAnalytics"],
      title: "Requests scored as attacks were answered normally",
      why: "Cloudflare's machine-learning attack score flagged these requests (SQL injection, XSS, command injection), and nothing stopped them before the origin answered.",
      fix: "Add a custom WAF rule that blocks or challenges requests with cf.waf.score lt 20 (start with Log for a day to check for false positives).",
    },
    "TRF-003": {
      category: "Traffic",
      severity: "high",
      docs: `${DOCS}/waf/detections/leaked-credentials/`,
      requires: ["securityAnalytics", "wafRulesets"],
      title: "Login attempts with leaked passwords aren't stopped",
      why: "Login requests carried passwords known from public breaches and reached the application unchallenged: credential stuffing, which succeeds wherever a user reused that password.",
      fix: "1. Add a rule that challenges or blocks when cf.waf.credential_check.username_and_password_leaked is true. 2. Force a password reset for affected accounts.",
    },
    "TRF-004": {
      category: "Traffic",
      severity: "high",
      docs: `${DOCS}/waf/custom-rules/use-cases/`,
      requires: ["securityAnalytics"],
      attackPath: true,
      title: "A sensitive file or debug page is being served",
      why: "Paths like /.env, /.git/, /actuator/env or /server-status answered 200 with real content: these usually leak credentials, source code or internal state.",
      fix: "1. Remove the file or turn off the endpoint on the origin. 2. Rotate any credentials it exposed. 3. Add a WAF rule blocking these paths as a safety net.",
    },
    "TRF-005": {
      category: "Traffic",
      severity: "medium",
      docs: `${DOCS}/ssl/edge-certificates/additional-options/always-use-https/`,
      requires: ["securityAnalytics"],
      title: "Content is served over plain HTTP",
      why: "Visitors on these hostnames got real responses over unencrypted HTTP, which anyone on the network path can read or change.",
      fix: "Turn on Always Use HTTPS (SSL/TLS → Edge Certificates), and remove any rule that disables it for these hostnames.",
    },
    "TRF-006": {
      category: "Traffic",
      severity: "low",
      docs: `${DOCS}/ssl/edge-certificates/additional-options/minimum-tls/`,
      requires: ["securityAnalytics", "zoneSettings"],
      title: "Clients still connect with TLS 1.0 or 1.1",
      why: "Real clients are negotiating deprecated TLS versions. Raising the minimum to 1.2 will cut them off, so find out who they are first.",
      fix: "1. Identify the clients (Security → Analytics, filter by TLS version). 2. Update them or let them know. 3. Raise the minimum TLS version to 1.2.",
    },
    "TRF-007": {
      category: "Traffic",
      severity: "low",
      docs: `${DOCS}/waf/custom-rules/`,
      requires: ["securityAnalytics", "wafRulesets"],
      title: "Security rule hasn't matched anything in 30 days",
      why: "A rule that never matches is often aimed at a path or host that changed, so the protection people think they have isn't there.",
      fix: "Check the rule's expression against current traffic; fix it, or delete it if it's no longer needed.",
    },
    "TRF-008": {
      category: "Traffic",
      severity: "medium",
      docs: `${DOCS}/bots/concepts/bot-score/`,
      requires: ["securityAnalytics"],
      title: "Likely bots succeed on login and API endpoints",
      why: "Requests with a bot score under 30 (automated) and no verified-bot identity got successful answers on login and authentication paths.",
      fix: "Add a custom rule that challenges cf.bot_management.score lt 30 on login paths, or rate-limit them by IP and JA4 fingerprint.",
    },
    "TRF-009": {
      category: "Traffic",
      severity: "low",
      docs: `${DOCS}/dns/manage-dns-records/`,
      requires: ["securityAnalytics", "dnsRecords"],
      title: "A hostname with no DNS record receives heavy traffic",
      why: "Many requests arrive for a name you don't publish: often a record deleted while clients still use it, or a forgotten custom hostname that someone else could set up.",
      fix: "Find out where the traffic comes from (Security → Analytics, filter by host); restore the record, or redirect or block the hostname explicitly.",
    },
  },
  ({ inv, d }, report) => {
    const extraHosts = new Set([
      ...(inv.workerDomains || []).map((w) => w.hostname.toLowerCase()),
      ...(inv.pages || []).flatMap((p) => (p.domains || []).map((h) => h.toLowerCase())),
    ]);

    for (const z of inv.zones) {
      const a = z.analytics;
      if (!a) continue;
      const zone = z.name;
      const events = d.zone(zone, "security/events");
      const days = `${WINDOW_DAYS} days`;

      // TRF-001: managed rules overridden to log, and logging real matches.
      const overrides = logOverrides(z);
      if (overrides.length && a.logOnly) {
        const logged = a.logOnly.find((x) => x.source === "firewallManaged")?.count || 0;
        report("TRF-001", {
          zone,
          resource: zone,
          pass: logged === 0,
          confidence: "likely",
          link: events,
          detail: `Managed rules matched ${fmt(logged)} requests on ${zone} in the last ${days} and blocked none: ${overrides.join("; ")}.`,
          evidence: {
            chain: [
              { label: "Override", value: overrides.join("; ") },
              { label: `Matches logged in ${days}`, value: fmt(logged) },
              { label: "Blocked", value: "None: log only" },
            ],
          },
        });
      }

      if (a.attacksPassed) {
        const total = a.attacksPassed.reduce((n, x) => n + x.count, 0);
        report("TRF-002", {
          zone,
          resource: zone,
          pass: total < ATTACKS_MIN,
          severity: total >= ATTACKS_HIGH ? "high" : "medium",
          confidence: "likely",
          link: events,
          detail: `${fmt(total)} requests classed as attacks got an answer in the last ${days}: ${top(a.attacksPassed, 3, (x) => `${x.host}${x.path} (${fmt(x.count)})`)}.`,
          evidence: { chain: a.attacksPassed.slice(0, 6).map((x) => ({ label: `${x.host}${x.path}`, value: `${fmt(x.count)} requests` })) },
        });
      }

      // TRF-003: leaked-credential logins that succeeded, with nothing acting on the detection.
      if (a.leakedLogins && (a.leakedLogins.length || (z.leaked?.enabled && z.wafCustom !== undefined))) {
        const acted =
          usesCredentialCheck(z.wafCustom?.rules) ||
          usesCredentialCheck(z.rateLimit?.rules) ||
          (z.wafManaged?.rules || []).some((r) => r.enabled !== false && r.action === "execute" && r.action_parameters?.id === RULESET.leakedCredentials);
        const total = a.leakedLogins.reduce((n, x) => n + x.count, 0);
        report("TRF-003", {
          zone,
          resource: zone,
          pass: total === 0 || acted,
          confidence: "likely",
          link: d.zone(zone, "security/waf/custom-rules"),
          detail: `${fmt(total)} login attempts with leaked credentials reached the site in the last ${days}, and no rule acts on leaked-credential detection: ${top(a.leakedLogins, 3, (x) => `${x.host}${x.path} (${x.result.replace(/_/g, " ")}, HTTP ${x.status})`)}.`,
        });
      }

      // TRF-004: sensitive paths answered with a body that could be the file (see LEAK_CONTENT).
      const leaks = (a.sensitive ?? []).filter((x) => LEAK_CONTENT.has(x.contentType.toLowerCase()) && !BENIGN_SENSITIVE.test(x.path));
      for (const [key, rows] of groupBy(leaks, (x) => `${x.host}${x.path}`)) {
        const n = rows.reduce((s, x) => s + x.count, 0);
        report("TRF-004", {
          zone,
          resource: key,
          pass: false,
          confidence: "likely",
          link: events,
          detail: `${key} answered 200 with ${rows.map((r) => r.contentType || "unknown").join("/")} content ${fmt(n)} times in the last ${days}.`,
          evidence: {
            chain: [
              { label: "Request", value: `GET ${key}` },
              { label: "Response", value: `200, ${rows[0].contentType} body` },
              { label: `Requests in ${days}`, value: fmt(n) },
            ],
          },
        });
      }
      if (a.sensitive && !leaks.length) report("TRF-004", { zone, resource: zone, pass: true });

      if (a.plainHttp) {
        const busy = a.plainHttp.filter((x) => x.count >= PLAIN_HTTP_MIN);
        for (const x of busy) {
          report("TRF-005", {
            zone,
            resource: x.host,
            pass: false,
            confidence: "likely",
            link: d.zone(zone, "ssl-tls/edge-certificates"),
            detail: `${x.host} served ${fmt(x.count)} successful responses over plain HTTP in the last ${days}.`,
          });
        }
        if (!busy.length) report("TRF-005", { zone, resource: zone, pass: true });
      }

      if (z.settings && a.oldTls) {
        const old = a.oldTls.filter((x) => x.count >= OLD_TLS_MIN);
        report("TRF-006", {
          zone,
          resource: zone,
          pass: old.length === 0,
          confidence: "likely",
          link: d.zone(zone, "security/analytics"),
          detail: `${fmt(old.reduce((n, x) => n + x.count, 0))} requests used TLS 1.0 or 1.1 in the last ${days}: ${top(old, 3, (x) => `${x.host} (${x.protocol}, ${fmt(x.count)})`)}.`,
        });
      }

      // TRF-007: rules with no events in 30 days. Skip and log rules don't always produce events, so only acting rules count.
      if (a.ruleHits) {
        for (const [phase, rs] of [
          ["Custom rules", z.wafCustom],
          ["Rate limiting rules", z.rateLimit],
        ] as const) {
          for (const r of rs?.rules || []) {
            if (r.enabled === false || !r.id || !["block", "challenge", "managed_challenge", "js_challenge"].includes(String(r.action))) continue;
            report("TRF-007", {
              zone,
              // The ID keeps two rules with the same description apart.
              resource: `${r.description || String(r.expression).slice(0, 60)} (${r.id.slice(0, 8)})`,
              pass: (a.ruleHits[r.id] || 0) > 0,
              confidence: "likely",
              link: d.zone(zone, phase === "Custom rules" ? "security/waf/custom-rules" : "security/waf/rate-limiting-rules"),
              detail: `${phase}: "${r.description || r.expression}" (${r.action}) had no matches in the last ${a.ruleHitsDays} days.`,
            });
          }
        }
      }

      if (a.botsPassed) {
        const total = a.botsPassed.reduce((n, x) => n + x.count, 0);
        report("TRF-008", {
          zone,
          resource: zone,
          pass: total < BOTS_MIN,
          confidence: "likely",
          link: d.zone(zone, "security/bots"),
          detail: `${fmt(total)} requests from likely bots got successful answers on login and auth paths in the last ${days}: ${top(a.botsPassed, 3, (x) => `${x.host}${x.path} (${fmt(x.count)})`)}.`,
        });
      }

      // TRF-009: busy hostnames under the zone that no DNS record, Worker domain or Pages domain serves.
      if (z.dnsReadable && a.hosts) {
        const names = new Set(z.dns.map((r) => r.name.toLowerCase()));
        const wild = z.dns.filter((r) => r.name.startsWith("*.")).map((r) => r.name.toLowerCase().slice(1));
        const zl = zone.toLowerCase();
        const routed = (z.workerRoutes || []).map((r) =>
          String(r.pattern || "")
            .split("/")[0]
            .toLowerCase(),
        );
        const byRoute = (h: string) => routed.some((p) => p === h || (p.startsWith("*") && h.endsWith(p.slice(1))));
        const unknown = a.hosts.filter(
          (h) =>
            (h.host === zl || h.host.endsWith(`.${zl}`)) &&
            h.count >= UNKNOWN_HOST_MIN &&
            !names.has(h.host) &&
            !wild.some((w) => h.host.endsWith(w)) &&
            !extraHosts.has(h.host) &&
            !byRoute(h.host),
        );
        for (const h of unknown) {
          report("TRF-009", {
            zone,
            resource: h.host,
            pass: false,
            confidence: "likely",
            link: d.zone(zone, "dns/records"),
            detail: `${h.host} received ${fmt(h.count)} requests in the last ${days}, but there's no DNS record, Worker or Pages domain for it.`,
          });
        }
        if (!unknown.length) report("TRF-009", { zone, resource: zone, pass: true });
      }
    }
  },
);
