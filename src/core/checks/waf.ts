// WAF & bots: which protections are deployed and turned on. Reading inside the
// rules themselves lives in waf-rules.ts.

import { defineChecks } from "./define.ts";
import { proxiedZone } from "./helpers.ts";
import { prefixLength } from "./expr.ts";
import { RULESET, WEAK_SECURITY_LEVELS } from "../cf-constants.ts";
import type { Inventory, ZoneInventory } from "../types.ts";

/** IP Access allow rules this broad let most of the internet skip every security product. */
const BROAD_ALLOW_PREFIX = 16;
const WAF_DOCS = "https://developers.cloudflare.com/waf";

/** Is a managed ruleset deployed for this zone, at zone level or by an account-level (Enterprise) rule? */
function deployed(inv: Inventory, z: ZoneInventory, rulesetId: string): boolean {
  const executes = (
    rules: { action?: string; enabled?: boolean; action_parameters?: Record<string, any>; expression?: string }[] | undefined,
    account: boolean,
  ) =>
    (rules || []).some(
      (r) =>
        r.enabled !== false &&
        r.action === "execute" &&
        r.action_parameters?.id === rulesetId &&
        (!account || appliesToZone(String(r.expression || ""), z.name)),
    );
  return executes(z.wafManaged?.rules, false) || executes(inv.accountRulesets.http_request_firewall_managed?.rules, true);
}

/** Account-level rules scope zones with cf.zone.name; anything else applies to every zone. */
function appliesToZone(expr: string, zone: string): boolean {
  if (!/cf\.zone\.name/.test(expr)) return true;
  return new RegExp(`"${zone.replace(/\./g, "\\.")}"`).test(expr) && !/not\s+cf\.zone\.name|cf\.zone\.name\s+ne/.test(expr);
}

export default defineChecks(
  {
    "WAF-001": {
      category: "WAF & bots",
      severity: "critical",
      docs: "https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/",
      requires: ["wafRulesets", "accountRulesets"],
      title: "Cloudflare Managed Ruleset not deployed on a paid zone",
      why: "You pay for the managed WAF on this plan but it isn't inspecting traffic.",
      fix: "Deploy the Cloudflare Managed Ruleset under Security → WAF → Managed rules.",
    },
    "WAF-002": {
      category: "WAF & bots",
      severity: "medium",
      docs: "https://developers.cloudflare.com/waf/managed-rules/reference/owasp-core-ruleset/",
      requires: ["wafRulesets", "accountRulesets"],
      title: "OWASP Core Ruleset not deployed on a paid zone",
      why: "The OWASP ruleset catches generic injection and XSS patterns the Cloudflare ruleset doesn't.",
      fix: "Deploy the OWASP Core Ruleset in log mode first, tune false positives, then switch to block.",
    },
    "WAF-003": {
      category: "WAF & bots",
      severity: "low",
      docs: "https://developers.cloudflare.com/waf/rate-limiting-rules/",
      requires: ["wafRulesets", "accountRulesets"],
      title: "No rate limiting rules",
      why: "Login, API and RPC endpoints can be brute-forced or scraped without limits. Every plan includes at least one rule.",
      fix: "Add a rate limiting rule for your most sensitive paths under Security → WAF → Rate limiting rules.",
    },
    "WAF-004": {
      category: "WAF & bots",
      severity: "medium",
      docs: "https://developers.cloudflare.com/bots/get-started/",
      requires: ["bot"],
      title: "Bot protection is off",
      why: "Automated traffic (credential stuffing, scraping) reaches the origin unchallenged.",
      fix: "Turn on Bot Fight Mode (Free) or configure Super Bot Fight Mode to challenge definitely-automated traffic (Pro+).",
    },
    "WAF-005": {
      category: "WAF & bots",
      severity: "low",
      docs: "https://developers.cloudflare.com/bots/additional-configurations/block-ai-bots/",
      requires: ["bot"],
      title: "AI crawlers are not blocked",
      why: "AI scrapers can crawl the site freely. This is a policy choice; flagged so it is a deliberate one.",
      fix: "Decide on a policy and set Security → Bots → Block AI bots accordingly.",
    },
    "WAF-006": {
      category: "WAF & bots",
      severity: "medium",
      docs: "https://developers.cloudflare.com/waf/tools/security-level/",
      requires: ["zoneSettings"],
      title: "Security level is low or off",
      why: "Requests from IPs with a bad reputation are not challenged.",
      fix: "Set Security → Settings → Security level to Medium (or rely on custom rules if deliberately off).",
    },
    "WAF-007": {
      category: "WAF & bots",
      severity: "low",
      docs: "https://developers.cloudflare.com/waf/tools/browser-integrity-check/",
      requires: ["zoneSettings"],
      title: "Browser Integrity Check is off",
      why: "Requests with abusive or missing headers aren't filtered.",
      fix: "Turn on Security → Settings → Browser Integrity Check.",
    },
    "WAF-008": {
      category: "WAF & bots",
      severity: "low",
      docs: "https://developers.cloudflare.com/waf/detections/leaked-credentials/",
      requires: ["leakedCredentials"],
      title: "Leaked credential detection is off",
      why: "Logins with passwords known from breaches go unflagged. Available on all plans.",
      fix: "Turn on Security → Settings → Leaked credentials detection and act on the header in your app or a WAF rule.",
    },
    "WAF-009": {
      category: "WAF & bots",
      severity: "low",
      docs: "https://developers.cloudflare.com/page-shield/",
      requires: ["pageShield"],
      title: "Client-side script monitoring (Page Shield) is off",
      why: "A compromised third-party script (Magecart-style) on your pages would go unnoticed.",
      fix: "Turn on Security → Client-side security (script monitor).",
    },
    "WAF-010": {
      category: "WAF & bots",
      severity: "medium",
      docs: "https://developers.cloudflare.com/waf/custom-rules/skip/",
      requires: ["wafRulesets"],
      title: "Custom rule skips the managed WAF",
      why: "Requests matching this rule bypass managed WAF inspection entirely.",
      fix: "Narrow the expression to exactly what needs the exception, or skip only specific managed rules instead of the whole ruleset.",
    },
    "WAF-011": {
      category: "WAF & bots",
      severity: "medium",
      docs: "https://developers.cloudflare.com/cache/reference/development-mode/",
      requires: ["zoneSettings"],
      title: "Development mode is on",
      why: "Development mode bypasses cache and is meant to be temporary.",
      fix: "Turn off Caching → Configuration → Development Mode.",
    },
    "WAF-019": {
      category: "WAF & bots",
      severity: "high",
      docs: "https://developers.cloudflare.com/ddos-protection/managed-rulesets/http/override-parameters/",
      requires: ["ddosRules"],
      title: "HTTP DDoS protection set to log only or low sensitivity",
      why: "Layer 7 DDoS attacks reach the origin instead of being stopped at the edge.",
      fix: "Under Security → DDoS → HTTP DDoS attack protection, remove the override, or set the action back to the default and the sensitivity to High.",
    },
    "WAF-020": {
      category: "WAF & bots",
      severity: "high",
      docs: `${WAF_DOCS}/tools/ip-access-rules/`,
      requires: ["firewallRules", "accountIpRules"],
      attackPath: true,
      title: "IP Access rule allowlists a whole country, network or large IP range",
      why: "Allowlisted requests skip the WAF, rate limiting and bot protection entirely, so anyone in that range is never inspected.",
      fix: "1. Open Security → WAF → Tools (or the account's IP Access rules). 2. Replace the allow rule with specific addresses, or a custom rule that skips only what's needed.",
    },
    "WAF-021": {
      category: "WAF & bots",
      severity: "medium",
      docs: "https://developers.cloudflare.com/rules/normalization/",
      requires: ["urlNormalization"],
      title: "URL normalization is off",
      why: "Without normalization, encoded or doubled characters in a path (/%61dmin, //admin) can slip past rules that match on the path.",
      fix: "Under Rules → Settings → URL normalization, normalize incoming URLs (Cloudflare normalization).",
    },
    "WAF-022": {
      category: "WAF & bots",
      severity: "high",
      docs: "https://developers.cloudflare.com/api-shield/security/mtls/configure/",
      requires: ["tlsSettings", "wafRulesets"],
      title: "mTLS is on for a hostname but no rule enforces it",
      why: "Turning on client certificates only asks for one. Unless a rule blocks requests without a valid certificate, anyone can still connect.",
      fix: "Add a custom WAF rule that blocks requests to the hostname when cf.tls_client_auth.cert_verified is false.",
    },
    "WAF-023": {
      category: "WAF & bots",
      severity: "high",
      docs: "https://developers.cloudflare.com/page-shield/detection/review-malicious-scripts/",
      requires: ["pageShield"],
      title: "Page Shield found a malicious script on your pages",
      why: "A script flagged as malicious runs in your visitors' browsers: card skimmers and credential stealers work this way.",
      fix: "1. Open Security → Page Shield → Scripts and find where the script is loaded. 2. Remove it, or block it with a content security policy.",
    },
  },
  ({ inv, d }, report) => {
    // IP Access allow rules, account-wide and per zone.
    const broadAllow = (r: { mode: string; configuration?: { target?: string; value?: string } }) => {
      if (r.mode !== "whitelist") return null;
      const t = r.configuration?.target,
        v = String(r.configuration?.value || "");
      if (t === "country") return `every visitor from ${v}`;
      if (t === "asn") return `all of network ${v}`;
      if (t === "ip_range" && prefixLength(v) <= BROAD_ALLOW_PREFIX) return `${v} (${(2 ** (32 - prefixLength(v))).toLocaleString("en-US")} addresses)`;
      return null;
    };
    for (const r of inv.accountIpRules || []) {
      const why = broadAllow(r);
      report("WAF-020", {
        resource: `${r.configuration?.target} ${r.configuration?.value}`,
        pass: !why,
        link: d.ipRules,
        detail: `An account-wide IP Access rule allows ${why}${r.notes ? ` ("${r.notes}")` : ""} to skip security on every zone.`,
      });
    }

    for (const z of inv.zones) {
      if (!z.settings || !proxiedZone(z)) continue;
      const s = z.settings,
        zone = z.name;
      const waf = d.zone(zone, "security/waf");

      if (z.plan !== "free" && z.wafManaged !== undefined) {
        report("WAF-001", { zone, resource: zone, pass: deployed(inv, z, RULESET.cloudflareManaged), detail: `Plan: ${z.planName}.`, link: waf });
        report("WAF-002", { zone, resource: zone, pass: deployed(inv, z, RULESET.owasp), detail: `Plan: ${z.planName}.`, link: waf });
      }
      if (z.rateLimit !== undefined) {
        const zoneRules = (z.rateLimit?.rules || []).filter((r) => r.enabled !== false).length;
        const accountRules = (inv.accountRulesets.http_ratelimit?.rules || []).filter(
          (r) => r.enabled !== false && appliesToZone(String(r.expression || ""), zone),
        ).length;
        report("WAF-003", { zone, resource: zone, pass: zoneRules + accountRules > 0, link: d.zone(zone, "security/waf/rate-limiting-rules") });
      }
      if (z.wafCustom !== undefined) {
        const skips = (z.wafCustom?.rules || []).filter(
          (r) => r.enabled !== false && r.action === "skip" && (r.action_parameters?.phases || []).includes("http_request_firewall_managed"),
        );
        for (const r of skips) {
          report("WAF-010", {
            zone,
            resource: r.description || String(r.expression).slice(0, 80),
            pass: false,
            link: d.zone(zone, "security/waf/custom-rules"),
            detail: `Skips: ${(r.action_parameters?.phases || []).join(", ")}.`,
            evidence: { expression: r.expression },
          });
        }
        if (!skips.length) report("WAF-010", { zone, resource: zone, pass: true });
      }

      if (z.bot) {
        const bots = d.zone(zone, "security/bots");
        const on = z.plan === "free" ? !!z.bot.fight_mode : ["block", "managed_challenge"].includes(z.bot.sbfm_definitely_automated);
        if (z.plan !== "enterprise") {
          report("WAF-004", {
            zone,
            resource: zone,
            pass: on,
            link: bots,
            detail:
              z.plan === "free"
                ? "Bot Fight Mode is off."
                : `Super Bot Fight Mode: definitely automated traffic is set to "${z.bot.sbfm_definitely_automated}".`,
          });
        }
        report("WAF-005", {
          zone,
          resource: zone,
          pass: z.bot.ai_bots_protection === "block",
          detail: `Block AI bots: ${z.bot.ai_bots_protection}.`,
          link: bots,
        });
      }
      const secSettings = d.zone(zone, "security/settings");
      report("WAF-006", {
        zone,
        resource: zone,
        pass: !WEAK_SECURITY_LEVELS.includes(String(s.security_level)),
        detail: `Security level: ${s.security_level}.`,
        link: secSettings,
      });
      report("WAF-007", { zone, resource: zone, pass: s.browser_check === "on", link: secSettings });
      if (z.leaked) report("WAF-008", { zone, resource: zone, pass: !!z.leaked.enabled, link: secSettings });
      if (z.pageShield) report("WAF-009", { zone, resource: zone, pass: !!z.pageShield.enabled, link: d.zone(zone, "security/page-shield") });
      report("WAF-011", { zone, resource: zone, pass: s.development_mode !== "on", link: d.zone(zone, "caching/configuration") });

      // WAF-019: DDoS overrides.
      if (z.ddos) {
        const weak: string[] = [];
        for (const r of z.ddos.rules || []) {
          if (r.enabled === false || r.action !== "execute") continue;
          const o = r.action_parameters?.overrides || {};
          if (o.action === "log") weak.push("every rule set to log only");
          if (o.sensitivity_level === "eoff" || o.sensitivity_level === "low")
            weak.push(`sensitivity set to ${o.sensitivity_level === "eoff" ? "Essentially off" : "Low"}`);
          for (const x of o.rules || []) {
            if (x.action === "log") weak.push(`rule ${x.id} set to log only`);
            if (x.sensitivity_level === "eoff" || x.sensitivity_level === "low") weak.push(`rule ${x.id} sensitivity ${x.sensitivity_level}`);
          }
        }
        report("WAF-019", {
          zone,
          resource: zone,
          pass: !weak.length,
          link: d.zone(zone, "security/ddos"),
          detail: `HTTP DDoS protection: ${weak.slice(0, 4).join("; ")}.`,
          evidence: weak.length ? { chain: weak.map((w) => ({ label: "Override", value: w })) } : null,
        });
      }

      for (const r of z.ipRules || []) {
        if (r.scope?.type && r.scope.type !== "zone") continue;
        const why = broadAllow(r);
        report("WAF-020", {
          zone,
          resource: `${r.configuration?.target} ${r.configuration?.value}`,
          pass: !why,
          link: d.zone(zone, "security/waf/tools"),
          detail: `An IP Access rule on ${zone} allows ${why}${r.notes ? ` ("${r.notes}")` : ""} to skip the WAF, rate limiting and bot protection.`,
        });
      }

      if (z.urlNormalization) {
        report("WAF-021", {
          zone,
          resource: zone,
          pass: z.urlNormalization.scope !== "none",
          link: d.zone(zone, "rules/settings"),
          detail: "Incoming URLs aren't normalized before rules run.",
        });
      }

      if (z.mtlsHostnames?.length && z.wafCustom !== undefined) {
        const enforced = (z.wafCustom?.rules || []).some(
          (r) => r.enabled !== false && r.action === "block" && /cf\.tls_client_auth\.cert_verified/.test(String(r.expression)),
        );
        for (const h of z.mtlsHostnames) {
          report("WAF-022", {
            zone,
            resource: h,
            pass: enforced,
            link: d.zone(zone, "security/waf/custom-rules"),
            detail: `Client certificates are requested on ${h}, but no custom rule blocks requests without a valid one.`,
          });
        }
      }

      let malicious = 0;
      for (const sc of z.pageShieldScripts || []) {
        const bad =
          sc.url_reported_malicious ||
          sc.domain_reported_malicious ||
          (sc.malicious_domain_categories || []).length > 0 ||
          (sc.malicious_url_categories || []).length > 0;
        if (!bad) continue;
        malicious++;
        const cats = [...(sc.malicious_url_categories || []), ...(sc.malicious_domain_categories || [])];
        report("WAF-023", {
          zone,
          resource: sc.url,
          pass: false,
          confidence: "confirmed",
          link: d.zone(zone, "security/page-shield"),
          detail: `${sc.url} is loaded on ${zone}${cats.length ? ` and is classed as ${cats.join(", ")}` : " and is reported as malicious"}.`,
        });
      }
      if (z.pageShieldScripts && !malicious) report("WAF-023", { zone, resource: zone, pass: true });
    }
  },
);
