// Change risk: protections weakened in the last 7 days, read from the audit log's
// before/after values. These age out on their own once the event is older than 7 days.

import { defineChecks } from "./define.ts";
import { emailDomain } from "./helpers.ts";
import { OLD_TLS, WEAK_SECURITY_LEVELS } from "../cf-constants.ts";
import type { Api } from "../types.ts";

const SECURITY_ACTIONS = new Set(["block", "challenge", "js_challenge", "managed_challenge", "execute", "skip"]);
const SECURITY_PHASES = new Set(["http_request_firewall_custom", "http_request_firewall_managed", "http_ratelimit", "http_request_sbfm"]);

// Zone setting names as they appear in audit metadata, and what counts as weaker.
const WEAKER: Record<string, (v: Api) => boolean> = {
  ssl: (v) => ["off", "flexible"].includes(String(v).toLowerCase()),
  "security level": (v) => WEAK_SECURITY_LEVELS.includes(String(v).toLowerCase().replace(/\s+/g, "_")),
  "always use https": (v) => v === false || v === "off",
  "minimum tls version": (v) => OLD_TLS.includes(String(v)),
  "browser integrity check": (v) => v === false || v === "off",
  waf: (v) => v === false || v === "off",
  "tls 1.3": (v) => v === false || v === "off",
  "development mode": (v) => v === true || v === "on",
};

const parse = (v: Api) => {
  if (v && typeof v === "object") return v;
  try {
    return JSON.parse(String(v || "null"));
  } catch {
    return null;
  }
};

export default defineChecks(
  {
    "CHG-001": {
      category: "Change risk",
      severity: "high",
      attackPath: true,
      docs: "https://developers.cloudflare.com/fundamentals/account/account-security/review-audit-logs/",
      requires: ["auditLogs"],
      title: "Security rule disabled or deleted recently",
      why: "Turning off a block, challenge or rate limiting rule removes protection immediately, and is easy to forget to undo.",
      fix: "Confirm the change was intended. Re-enable the rule, or record why it was removed.",
    },
    "CHG-002": {
      category: "Change risk",
      severity: "medium",
      attackPath: true,
      docs: "https://developers.cloudflare.com/fundamentals/account/account-security/review-audit-logs/",
      requires: ["auditLogs"],
      title: "Access policy widened recently",
      why: "Adding Everyone, a Bypass rule or outside email addresses lets more people into an internal application.",
      fix: "Confirm the change with the application owner, and prefer identity-provider groups over individual addresses.",
    },
    "CHG-003": {
      category: "Change risk",
      severity: "high",
      attackPath: true,
      docs: "https://developers.cloudflare.com/fundamentals/account/account-security/review-audit-logs/",
      requires: ["auditLogs"],
      title: "Zone security setting lowered recently",
      why: "A weaker SSL mode, security level or TLS minimum applies to all traffic the moment it's saved.",
      fix: "Confirm the change was intended and restore the stronger setting.",
    },
  },
  ({ inv, d, org: ours }, report) => {
    if (!inv.audit) return;
    const when = (a: Api): string =>
      String(a.when || "")
        .slice(0, 16)
        .replace("T", " ");
    const who = (a: Api): string => a.actor?.email || a.actor?.type || "unknown";
    const zoneName = (a: Api): string | null => a.metadata?.zone_name || null;

    for (const a of inv.audit) {
      const type = String(a.action?.type || "");
      if (a.action?.result === false) continue;

      // CHG-001: security rules disabled, removed, or whole security rulesets deleted
      if (type === "rulesets_update") {
        const before: Api[] = parse(a.oldValueJson)?.modified_rules || [];
        const after: Api[] = parse(a.newValueJson)?.modified_rules || [];
        for (const b of before) {
          const n = after.find((x) => (x.id && x.id === b.id) || (x.description && x.description === b.description));
          if (!n || !SECURITY_ACTIONS.has(b.action)) continue;
          if (b.enabled !== false && n.enabled === false) {
            report("CHG-001", {
              zone: zoneName(a),
              resource: `"${b.description || b.expression?.slice(0, 60)}" disabled ${when(a)}`,
              pass: false,
              detail: `${who(a)} turned off the ${b.action} rule "${b.description || b.expression}" at ${when(a)} UTC.`,
              evidence: {
                chain: [
                  { label: "When", value: `${when(a)} UTC` },
                  { label: "Who", value: `${who(a)}${a.actor?.ip ? ` from ${a.actor.ip}` : ""}` },
                  { label: "Rule", value: `${b.action}: ${b.expression}` },
                ],
              },
              link: zoneName(a) ? d.zone(zoneName(a)!, "security/waf") : null,
            });
          }
        }
      }
      if (type === "rulesets_delete" && SECURITY_PHASES.has(parse(a.oldValueJson)?.phase)) {
        report("CHG-001", {
          zone: zoneName(a),
          resource: `${parse(a.oldValueJson)?.phase} ruleset deleted ${when(a)}`,
          pass: false,
          detail: `${who(a)} deleted the ${parse(a.oldValueJson)?.phase} ruleset at ${when(a)} UTC.`,
          link: null,
        });
      }

      // CHG-002: Access policies that now let more people in
      if (/^access_(update|create)(_application)?_policy$/.test(type)) {
        const before = parse(a.oldValue) || {},
          after = parse(a.newValue) || {};
        const incl = (p: Api) => [...(p.include || []), ...(p.policies || []).flatMap((x: Api) => x.include || [])];
        const key = (r: Api) => JSON.stringify(r);
        const had = new Set(incl(before).map(key));
        const added = incl(after).filter((r: Api) => !had.has(key(r)));
        const widened = added.filter(
          (r: Api) =>
            r.everyone ||
            (r.email?.email && !ours.has(emailDomain(r.email.email))) ||
            (r.email_domain?.domain && !ours.has(String(r.email_domain.domain).toLowerCase())),
        );
        if (after.decision === "bypass" && before.decision !== "bypass") widened.push({ bypass: true });
        if (widened.length) {
          const desc = widened
            .map((r: Api) => (r.everyone ? "Everyone" : r.bypass ? "a Bypass decision" : r.email?.email || r.email_domain?.domain))
            .join(", ");
          report("CHG-002", {
            zone: null,
            resource: `${after.name || before.name || "Access policy"} ${when(a)}`,
            pass: false,
            detail: `${who(a)} changed "${after.name || before.name || "an Access policy"}" at ${when(a)} UTC to also allow ${desc}.`,
            evidence: {
              chain: [
                { label: "When", value: `${when(a)} UTC` },
                { label: "Who", value: who(a) },
                { label: "Added", value: desc },
              ],
            },
            link: d.zt("access/policies"),
          });
        }
      }

      // CHG-003: zone security settings lowered
      if (type === "change_setting" && a.metadata?.name) {
        const name = String(a.metadata.name).toLowerCase();
        const check = WEAKER[name];
        if (check?.(a.metadata.value)) {
          report("CHG-003", {
            zone: zoneName(a),
            resource: `${a.metadata.name} on ${zoneName(a) || "zone"} ${when(a)}`,
            pass: false,
            detail: `${who(a)} set ${a.metadata.name} to ${String(a.metadata.value)}${zoneName(a) ? ` on ${zoneName(a)}` : ""} at ${when(a)} UTC.`,
            link: zoneName(a) ? d.zone(zoneName(a)!) : null,
          });
        }
      }
    }
    // One passing evaluation per check when the week was clean, so the category is scored.
    for (const id of ["CHG-001", "CHG-002", "CHG-003"] as const) report.passIfNone(id, "last 7 days");
  },
);
