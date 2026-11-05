// Imports Cloudflare Security Center insights as findings. Where one of our own
// checks already reports the same problem, the insight is attached to that
// finding as corroboration instead of being listed twice.

import { SC_CLASSES, SC_SEVERITY } from "../catalog.ts";
import type { Inventory, Result } from "../types.ts";

const ISSUE_TYPE_CATEGORY: Record<string, string> = {
  exposed_infrastructure: "DNS",
  insecure_configuration: "TLS & HTTPS",
  configuration_suggestion: "WAF & bots",
  compliance_violation: "TLS & HTTPS",
  email_security: "Email",
  weak_authentication: "Identity & access",
};

export function securityCenterFindings(inv: Inventory, customFailures: Result[], disabled: Set<string>): Result[] {
  if (!inv.insights) return [];
  const zoneName: Record<string, string> = Object.fromEntries(inv.zones.map((z) => [z.id, z.name]));
  const out: Result[] = [];
  for (const i of inv.insights) {
    if (i.dismissed || disabled.has(`SC:${i.issue_class}`)) continue;
    const meta: { title?: string; category?: string; covers?: string } = SC_CLASSES[i.issue_class] || {};
    const zone = zoneName[i.payload?.zone_tag] || null;
    const subject = String(i.subject || "").toLowerCase();

    if (meta.covers) {
      // Same resource, or our zone-level finding covers a hostname in that zone.
      const match = customFailures.find(
        (f) =>
          f.checkId === meta.covers &&
          (f.resource.toLowerCase() === subject ||
            f.resource.toLowerCase().startsWith(subject + " ") ||
            (f.zone && (f.zone === subject || (f.zone === zone && f.resource === f.zone)))),
      );
      if (match) {
        (match.corroborated ||= []).push(i.issue_class);
        continue;
      }
    }

    const p = i.payload || {};
    const bits: string[] = [];
    if (p.dns_record_content) bits.push(`Points to ${p.dns_record_content.replace(/\.$/, "")}`);
    if (p.asn_name) bits.push(`network: ${p.asn_name}`);
    if (p.dns_queries != null) bits.push(`${p.dns_queries} DNS queries`);
    if (p.detection_method && !p.detection_method.startsWith("security_center.")) bits.push(p.detection_method);
    for (const x of p.issues || []) bits.push(x.message + (x.offending_text ? ` (${x.offending_text})` : ""));

    out.push({
      checkId: `SC:${i.issue_class}`,
      source: "security_center",
      zone,
      resource: i.subject || zone || "account",
      pass: false,
      severity: SC_SEVERITY[i.severity] || "medium",
      category: meta.category || ISSUE_TYPE_CATEGORY[i.issue_type] || "Platform",
      title: meta.title || humanize(i.issue_class),
      detail: bits.join(". ") + (i.since ? `. Open since ${i.since.slice(0, 10)}.` : ""),
      evidence: { issue_type: i.issue_type, issue_class: i.issue_class, id: i.id },
      link: i.resolve_link
        ? `https://dash.cloudflare.com${i.resolve_link.replace(":account_id", inv.accountId).replace(":zone_name", zone || "")}`
        : `https://dash.cloudflare.com/${inv.accountId}/security-center`,
    });
  }
  return out;
}

const humanize = (s: string) => s.replace(/_/g, " ").replace(/^./, (c) => c.toUpperCase());
