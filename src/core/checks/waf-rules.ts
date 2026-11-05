// WAF & bots, read from inside the rules: overrides that weaken managed rules,
// exceptions keyed on forgeable input, stale hostnames, toothless rate limits,
// per-path security downgrades and hard-coded secrets.

import { defineChecks } from "./define.ts";
import { proxiedZone } from "./helpers.ts";
import { rulesetName, WEAK_SECURITY_LEVELS } from "../cf-constants.ts";
import type { Rule, Ruleset } from "../cf-types.ts";
import { broadNetwork, hostsIn, spoofableOnly } from "./expr.ts";
import type { Api, ZoneInventory } from "../types.ts";

const WEAK_CONFIG: Record<string, (v: Api) => string | null> = {
  security_level: (v) => (WEAK_SECURITY_LEVELS.includes(v) ? `security level ${v}` : null),
  ssl: (v) => (["off", "flexible"].includes(v) ? `SSL ${v}` : null),
  bic: (v) => (v === false ? "Browser Integrity Check off" : null),
  browser_check: (v) => (v === "off" || v === false ? "Browser Integrity Check off" : null),
  waf: (v) => (v === "off" || v === false ? "WAF off" : null),
  disable_security: (v) => (v ? "all security features off" : null),
  automatic_https_rewrites: () => null,
};

/** Every rule of every phase in a zone, labelled with where it lives. */
function allRules(z: ZoneInventory): { phase: string; rule: Rule }[] {
  const out: { phase: string; rule: Rule }[] = [];
  const add = (phase: string, rs: Ruleset | null | undefined) => {
    for (const rule of rs?.rules || []) if (rule.enabled !== false) out.push({ phase, rule });
  };
  add("Custom rules", z.wafCustom);
  add("Rate limiting rules", z.rateLimit);
  add("Managed rules", z.wafManaged);
  const names: Record<string, string> = {
    http_config_settings: "Configuration rules",
    http_request_transform: "URL rewrite rules",
    http_request_late_transform: "Request header rules",
    http_request_dynamic_redirect: "Redirect rules",
    http_request_cache_settings: "Cache rules",
    http_request_origin: "Origin rules",
    http_response_headers_transform: "Response header rules",
    http_log_custom_fields: "Custom log fields",
  };
  for (const [ph, rs] of Object.entries(z.phases)) add(names[ph] || ph, rs);
  return out;
}

const label = (r: Rule) => r.description || String(r.expression || "").slice(0, 80);

export default defineChecks(
  {
    "WAF-012": {
      category: "WAF & bots",
      severity: "high",
      attackPath: true,
      docs: "https://developers.cloudflare.com/waf/managed-rules/deploy-zone-dashboard/",
      requires: ["wafRulesets"],
      title: "Managed rules weakened by overrides",
      why: "The managed ruleset is deployed, but overrides switch rules or whole categories to log-only or off, so matching attacks pass through.",
      fix: "Review the overrides under Security → WAF → Managed rules. Keep exceptions as narrow as possible, scoped to the paths that need them.",
    },
    "WAF-013": {
      category: "WAF & bots",
      severity: "high",
      attackPath: true,
      docs: "https://developers.cloudflare.com/waf/custom-rules/skip/",
      requires: ["wafRulesets"],
      title: "Security skipped based on a field anyone can set",
      why: "Headers, cookies, the User-Agent and the query string are chosen by the client. Anyone who learns the value skips your security rules.",
      fix: "Base the exception on something an attacker can't forge: a source IP list, mTLS, a verified bot, or a Cloudflare Access service token.",
    },
    "WAF-014": {
      category: "WAF & bots",
      severity: "medium",
      docs: "https://developers.cloudflare.com/waf/custom-rules/skip/",
      requires: ["wafRulesets"],
      title: "Security skipped for a very broad IP range or network",
      why: "Exempting a large CIDR or a whole network (ASN) usually includes cloud providers that attackers rent by the hour.",
      fix: "Narrow the exception to the specific addresses that need it, ideally kept in an IP list.",
    },
    "WAF-015": {
      category: "WAF & bots",
      severity: "low",
      docs: "https://developers.cloudflare.com/ruleset-engine/rules-language/",
      requires: ["wafRulesets", "otherRulesets", "pageRules", "dnsRecords"],
      title: "Rule targets a hostname that no longer exists",
      why: "Rules for removed hostnames are dead configuration, and they often mean protection was meant for a host that has since moved.",
      fix: "Update the rule to the current hostname, or delete it.",
    },
    "WAF-016": {
      category: "WAF & bots",
      severity: "low",
      docs: "https://developers.cloudflare.com/waf/rate-limiting-rules/best-practices/",
      requires: ["wafRulesets"],
      title: "Rate limiting rule that never limits",
      why: "A rule that only logs, or that allows more than 50 requests per second from one IP, won't stop brute force or scraping.",
      fix: "Switch the action to block or managed challenge and set a threshold based on normal traffic for that path.",
    },
    "WAF-017": {
      category: "WAF & bots",
      severity: "medium",
      docs: "https://developers.cloudflare.com/rules/configuration-rules/",
      requires: ["otherRulesets", "pageRules"],
      title: "Configuration or page rule lowers security for some traffic",
      why: "Per-path rules that turn off the security level, Browser Integrity Check or SSL quietly carve holes in zone-wide protection.",
      fix: "Scope the rule as narrowly as possible, or remove it. Page Rules are deprecated; move what's needed to Configuration Rules.",
    },
    "WAF-018": {
      category: "WAF & bots",
      severity: "medium",
      docs: "https://developers.cloudflare.com/rules/transform/request-header-modification/",
      requires: ["otherRulesets"],
      title: "Secret hard-coded in a transform rule",
      why: "Anyone with read access to this zone (members, API tokens, tools like this one) can read the value, and the origin trusts it.",
      fix: "Rotate the secret. Lock the origin with Authenticated Origin Pulls or a Cloudflare Tunnel instead of a shared header.",
    },
  },
  ({ inv, d }, report) => {
    for (const z of inv.zones) {
      if (!proxiedZone(z)) continue;
      const zone = z.name;
      const wafLink = d.zone(zone, "security/waf");

      // WAF-012: overrides on deployed managed rulesets
      for (const r of z.wafManaged?.rules || []) {
        if (r.action !== "execute" || r.enabled === false) continue;
        const o = r.action_parameters?.overrides || {};
        const weak: string[] = [];
        if (o.enabled === false) weak.push("the whole ruleset is turned off");
        if (o.action === "log") weak.push("every rule is set to log only");
        for (const c of o.categories || []) {
          if (/^paranoia-level-[234]$/.test(c.category)) continue;
          if (c.enabled === false) weak.push(`category "${c.category}" turned off`);
          else if (c.action === "log") weak.push(`category "${c.category}" set to log only`);
        }
        const ruleOff = (o.rules || []).filter((x: Api) => x.enabled === false).length;
        const ruleLog = (o.rules || []).filter((x: Api) => x.action === "log").length;
        if (ruleOff) weak.push(`${ruleOff} rule${ruleOff === 1 ? "" : "s"} turned off`);
        if (ruleLog) weak.push(`${ruleLog} rule${ruleLog === 1 ? "" : "s"} set to log only`);
        const high = (o.rules || []).find((x: Api) => typeof x.score_threshold === "number" && x.score_threshold > 60);
        if (high) weak.push(`anomaly score threshold raised to ${high.score_threshold}`);
        if (o.sensitivity_level === "low" || o.sensitivity_level === "eoff") weak.push(`sensitivity set to ${o.sensitivity_level}`);
        const name = rulesetName(r.action_parameters?.id);
        report("WAF-012", {
          zone,
          resource: `${name} (${zone})`,
          pass: weak.length === 0,
          severity: o.enabled === false || o.action === "log" ? "high" : "medium",
          detail: `${name}: ${weak.join("; ")}.`,
          evidence: { chain: weak.map((w) => ({ label: name, value: w })) },
          link: wafLink,
        });
      }

      // WAF-013 / WAF-014: exceptions on forgeable input or broad networks
      const skips = (z.wafCustom?.rules || []).filter((r: Api) => r.enabled !== false && r.action === "skip");
      for (const r of skips) {
        const spoof = spoofableOnly(String(r.expression || ""));
        report("WAF-013", {
          zone,
          resource: label(r),
          pass: !spoof,
          detail: spoof ? `This rule skips ${skipped(r)} when the request has ${spoof.join(" or ")}. Any client can send that.` : "",
          evidence: spoof
            ? {
                chain: [
                  { label: "Condition", value: String(r.expression) },
                  { label: "Forgeable input", value: spoof.join(", ") },
                  { label: "Skips", value: skipped(r) },
                ],
              }
            : null,
          link: d.zone(zone, "security/waf/custom-rules"),
        });
        const broad = broadNetwork(String(r.expression || ""));
        report("WAF-014", {
          zone,
          resource: label(r),
          pass: !broad,
          detail: broad ? `This rule skips ${skipped(r)} for ${broad}.` : "",
          link: d.zone(zone, "security/waf/custom-rules"),
        });
      }

      // WAF-015: rules that reference hostnames with no DNS record
      const names = new Set(z.dns.map((r) => String(r.name).toLowerCase()));
      const wild = z.dns.filter((r) => String(r.name).startsWith("*.")).map((r) => String(r.name).toLowerCase().slice(1));
      const exists = (h: string) => names.has(h) || wild.some((w) => h.endsWith(w));
      let ruleHosts = 0;
      for (const { phase, rule } of allRules(z)) {
        for (const h of hostsIn(String(rule.expression || ""))) {
          if (!(h === zone || h.endsWith(`.${zone}`))) continue;
          ruleHosts++;
          if (!exists(h))
            report("WAF-015", {
              zone,
              resource: `${h} in "${label(rule)}"`,
              pass: false,
              detail: `${phase}: "${label(rule)}" matches ${h}, which has no DNS record.`,
              link: wafLink,
            });
        }
      }
      for (const p of z.pageRules || []) {
        const target = String(p.targets?.[0]?.constraint?.value || "");
        const h = target
          .replace(/^https?:\/\//, "")
          .split("/")[0]
          .toLowerCase();
        if (!h || h.includes("*")) continue;
        ruleHosts++;
        if (!exists(h))
          report("WAF-015", {
            zone,
            resource: `${h} in page rule`,
            pass: false,
            detail: `Page rule for ${target} matches a hostname with no DNS record.`,
            link: d.zone(zone, "rules/page-rules"),
          });
      }
      if (ruleHosts) report("WAF-015", { zone, resource: zone, pass: true });

      // WAF-016: rate limits that never limit
      for (const r of z.rateLimit?.rules || []) {
        if (r.enabled === false) continue;
        const rl = r.ratelimit || {};
        const rps = rl.requests_per_period && rl.period ? rl.requests_per_period / rl.period : null;
        const why =
          r.action === "log" ? "only logs matches" : rps != null && rps > 50 ? `allows ${Math.round(rps)} requests per second from each client` : null;
        report("WAF-016", {
          zone,
          resource: label(r),
          pass: !why,
          detail: why ? `"${label(r)}" ${why}.` : "",
          link: d.zone(zone, "security/waf/rate-limiting-rules"),
        });
      }

      // WAF-017: configuration and page rules that lower security
      let configRules = 0;
      for (const r of z.phases.http_config_settings?.rules || []) {
        if (r.enabled === false) continue;
        configRules++;
        const weak = Object.entries(r.action_parameters || {})
          .map(([k, v]) => WEAK_CONFIG[k]?.(v))
          .filter(Boolean) as string[];
        // Browser Integrity Check off on its own is routine for API hosts; anything stronger is a real downgrade.
        const severity = weak.every((w) => w.startsWith("Browser Integrity")) ? "low" : "medium";
        if (weak.length)
          report("WAF-017", {
            zone,
            resource: label(r),
            pass: false,
            severity,
            detail: `Configuration rule sets ${weak.join(", ")} for ${String(r.expression)}.`,
            link: d.zone(zone, "rules/configuration-rules"),
          });
      }
      for (const p of z.pageRules || []) {
        if (p.status === "disabled") continue;
        configRules++;
        const weak = (p.actions || [])
          .map((a: Api) => (a.id === "disable_security" ? "all security features off" : WEAK_CONFIG[a.id]?.(a.value)))
          .filter(Boolean) as string[];
        if (weak.length)
          report("WAF-017", {
            zone,
            resource: `Page rule ${p.targets?.[0]?.constraint?.value}`,
            pass: false,
            detail: `Page rule sets ${weak.join(", ")} for ${p.targets?.[0]?.constraint?.value}.`,
            link: d.zone(zone, "rules/page-rules"),
          });
      }
      if (configRules) report("WAF-017", { zone, resource: zone, pass: true });

      // WAF-018: static secrets in request-header transforms
      for (const ph of ["http_request_late_transform", "http_request_transform", "http_response_headers_transform"]) {
        const where = ph === "http_response_headers_transform" ? "Response header rule" : "Request header rule";
        for (const r of z.phases[ph]?.rules || []) {
          if (r.enabled === false) continue;
          for (const [hname, hv] of Object.entries(r.action_parameters?.headers || {}) as [string, Api][]) {
            const secret =
              hv?.operation === "set" && typeof hv.value === "string" && hv.value.length >= 16 && /auth|token|secret|key|password|signature|api/i.test(hname);
            report("WAF-018", {
              zone,
              resource: `${hname} in "${label(r)}"`,
              pass: !secret,
              detail: secret ? `${where} "${label(r)}" adds ${hname} with a fixed ${hv.value.length}-character value for ${String(r.expression)}.` : "",
              evidence: secret
                ? {
                    chain: [
                      { label: "Rule", value: label(r) },
                      { label: "Header", value: `${hname}: ${"•".repeat(8)} (${hv.value.length} characters, not shown)` },
                      { label: "Applies to", value: String(r.expression) },
                    ],
                  }
                : null,
              link: d.zone(zone, "rules/transform-rules"),
            });
          }
        }
      }
    }
  },
);

function skipped(r: Rule): string {
  const p = r.action_parameters || {};
  const parts: string[] = [];
  if (p.ruleset === "current") parts.push("all remaining custom rules");
  for (const ph of p.phases || [])
    parts.push(
      (
        { http_request_firewall_managed: "the managed WAF", http_ratelimit: "rate limiting", http_request_sbfm: "Super Bot Fight Mode" } as Record<
          string,
          string
        >
      )[ph] || ph,
    );
  for (const prod of p.products || []) parts.push(prod);
  return parts.length ? parts.join(", ") : "security rules";
}
