// The Vercel Firewall: whether it's on, which managed rulesets block rather than
// log, IP rules that let traffic skip it, and rate limiting. A project that was
// never configured runs Vercel's defaults: the firewall on, managed rulesets off.

import { defineChecks, plan } from "./define.ts";

/** IP rules wider than this (a /16 or bigger) let a whole network skip the firewall. */
const WIDE_PREFIX = 16;

const prefixOf = (ip: string): number => {
  const m = /\/(\d+)$/.exec(ip);
  if (m) return Number(m[1]);
  return ip.includes(":") ? 128 : 32;
};

export default defineChecks(
  {
    "VFW-001": {
      category: "WAF & bots",
      severity: "high",
      docs: "https://vercel.com/docs/vercel-firewall/vercel-waf",
      requires: ["firewall"],
      title: "Vercel Firewall is turned off",
      why: "With the firewall off, custom rules, IP blocks and managed rulesets don't run, so nothing filters attacks before they reach your functions.",
      fix: "Open the project's Firewall tab and turn the firewall on, then check its rules still match what you expect.",
    },
    "VFW-002": {
      category: "WAF & bots",
      severity: "low",
      docs: "https://vercel.com/docs/vercel-firewall/vercel-waf/managed-rulesets",
      requires: ["projects", "projectDomains", "firewall"],
      title: "Bot protection is off on a public site",
      why: "Automated traffic that pretends to be a browser reaches your pages and functions, running up usage and probing for weak spots. Vercel leaves bot protection off until you turn it on.",
      fix: "In the project's Firewall → Configure → Bot Management, turn on Bot Protection with the Challenge action.",
    },
    "VFW-003": {
      category: "WAF & bots",
      severity: "low",
      docs: "https://vercel.com/docs/vercel-firewall/vercel-waf/managed-rulesets",
      requires: ["firewall"],
      title: "AI crawlers aren't blocked",
      why: "AI crawlers copy your content and can generate heavy traffic. Blocking them is a choice; if you allow them, mark this as accepted.",
      fix: "In the project's Firewall → Configure → Bot Management, set AI Bots to Deny.",
    },
    "VFW-004": {
      category: "WAF & bots",
      severity: "medium",
      docs: "https://vercel.com/docs/vercel-firewall/vercel-waf/managed-rulesets#configure-owasp-core-ruleset",
      requires: ["firewall"],
      title: "OWASP rules are on but only logging",
      why: "The OWASP core ruleset matches injection attacks (SQL injection, cross-site scripting, remote code execution) but, in Log mode, lets every one of them through.",
      fix: "In the project's Firewall → Configure → OWASP Core Ruleset, check the logged matches for false positives, then set the rules to Deny.",
    },
    "VFW-005": {
      category: "WAF & bots",
      severity: "low",
      docs: "https://vercel.com/docs/vercel-firewall/vercel-waf/custom-rules",
      requires: ["firewall"],
      title: "Firewall rule only logs",
      why: "A rule in Log mode matches attacks but lets them through. It's meant for testing a new rule, and is easy to forget.",
      fix: "Check the rule's matches in the Firewall tab, then switch it to Deny or Challenge, or delete it.",
    },
    "VFW-006": {
      category: "WAF & bots",
      severity: "high",
      docs: "https://vercel.com/docs/vercel-firewall/vercel-waf/ip-blocking",
      requires: ["firewall"],
      attackPath: true,
      title: "A wide IP range skips the firewall",
      why: "A bypass rule for a large network turns the firewall off for everyone in it, including attackers who share that network or cloud provider.",
      fix: "Narrow the bypass to the exact addresses that need it, or delete it.",
    },
    "VFW-007": {
      category: "WAF & bots",
      severity: "low",
      docs: "https://vercel.com/docs/vercel-firewall/vercel-waf/rate-limiting",
      requires: ["firewall"],
      title: "No rate limiting rule",
      why: "Without a rate limit, one client can hammer login forms and API routes for credential stuffing or to run up function usage.",
      fix: "Add a custom rule with the Rate Limit action for login, sign-up and API paths in the project's Firewall tab.",
    },
  },
  ({ inv, d }, report) => {
    const p = plan(inv);
    for (const proj of inv.projects) {
      const fw = proj.firewall;
      if (!fw) continue;
      const link = d.firewall(proj.name);
      report("VFW-001", { zone: proj.name, resource: proj.name, pass: fw.enabled, detail: fw.configured ? "" : "Vercel's default settings", link });
      if (!fw.enabled) continue;

      // Vercel calls bot protection "bot_filter" on projects and "bot_protection" in the firewall API.
      const bots = fw.managedRules.bot_filter ?? fw.managedRules.bot_protection;
      const publicSite = (proj.domains ?? []).some((x) => !x.name.endsWith(".vercel.app") && !x.redirect && !x.gitBranch);
      // A project that only answers on *.vercel.app is rarely a public site worth a bot finding.
      if (publicSite) report("VFW-002", { zone: proj.name, resource: proj.name, pass: blocking(bots), detail: describe(bots), link });
      // AI crawlers are a choice; only ask once someone has started configuring the firewall.
      if (fw.configured)
        report("VFW-003", { zone: proj.name, resource: proj.name, pass: blocking(fw.managedRules.ai_bots), detail: describe(fw.managedRules.ai_bots), link });

      // The OWASP core ruleset: judged once some of its categories are on. Turned on but only logging is the finding.
      const crs = Object.entries(fw.crs ?? {}).filter(([, r]) => r.active);
      const owasp = fw.managedRules.owasp;
      if (crs.length || owasp?.active) {
        const logging = crs.filter(([, r]) => r.action === "log").map(([k]) => CRS_LABEL[k] ?? k);
        const blocks = crs.some(([, r]) => r.action !== "log") || (!!owasp?.active && owasp.action !== "log");
        report("VFW-004", {
          zone: proj.name,
          resource: proj.name,
          pass: blocks,
          detail: blocks ? "" : `On, but only logging: ${logging.join(", ") || "the managed OWASP ruleset"}`,
          link,
        });
      }

      for (const r of fw.rules.filter((x) => x.active))
        report("VFW-005", { zone: proj.name, resource: `${proj.name}: ${r.name}`, pass: r.action !== "log", link });
      report.passIfNone("VFW-005", proj.name, proj.name);

      for (const ip of fw.ips.filter((x) => x.action === "bypass"))
        report("VFW-006", {
          zone: proj.name,
          resource: `${proj.name}: ${ip.ip}`,
          pass: prefixOf(ip.ip) > WIDE_PREFIX,
          detail: `Bypass for ${ip.ip}${ip.hostname ? ` on ${ip.hostname}` : ""}`,
          link,
        });
      report.passIfNone("VFW-006", proj.name, proj.name);

      // Rate limits are a paid feature, and only worth asking about once the firewall is being configured.
      if (p !== "hobby" && fw.configured)
        report("VFW-007", { zone: proj.name, resource: proj.name, pass: fw.rules.some((r) => r.active && r.action === "rate_limit"), link });
    }
  },
);

/** The OWASP core ruleset's categories, as the Vercel dashboard names them. */
const CRS_LABEL: Record<string, string> = {
  sqli: "SQL injection",
  xss: "cross-site scripting",
  rce: "remote code execution",
  lfi: "local file inclusion",
  rfi: "remote file inclusion",
  gen: "generic attacks",
  ma: "multipart attacks",
  php: "PHP",
  java: "Java",
  sd: "scanner detection",
  sf: "session fixation",
};

const blocking = (r: { active: boolean; action: string | null } | undefined) => !!r?.active && r.action !== "log";

function describe(r: { active: boolean; action: string | null } | undefined): string {
  if (!r?.active) return "Off";
  return r.action === "log" ? "On, but only logging" : `On${r.action ? ` (${r.action})` : ""}`;
}
