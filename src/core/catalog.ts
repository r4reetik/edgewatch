// The catalog of checks (built from the check modules) and how Security Center
// insight classes map onto them. `severity` is a check's default; a finding may
// raise or lower it. `why` and `fix` are shown on each finding.

import { MODULES, type CheckId } from "./checks/index.ts";
import type { CheckMeta } from "./checks/define.ts";
import type { Severity } from "./types.ts";

export { CATEGORIES, type Category } from "./categories.ts";
export { SEVERITIES, SEVERITY_WEIGHT } from "../shared/severity.ts";
export type { CheckId } from "./checks/index.ts";

export interface CheckDef extends CheckMeta {
  id: CheckId;
}

/** Every check, built from the modules in checks/index.ts. */
export const CHECKS: CheckDef[] = MODULES.flatMap((m) => Object.entries(m.meta).map(([id, meta]) => ({ id: id as CheckId, ...(meta as CheckMeta) })));

export const CHECK_BY_ID: Record<string, CheckDef> = Object.fromEntries(CHECKS.map((x) => [x.id, x]));

// Security Center issue classes: readable titles, our categories, and which of our
// checks cover the same problem (used to avoid double-listing).
export const SC_CLASSES: Record<string, { title: string; category: string; covers?: string }> = {
  cname_record_not_proxied: { title: "CNAME record is not proxied (origin exposed)", category: "DNS" },
  a_record_not_proxied: { title: "A record is not proxied (origin IP exposed)", category: "DNS" },
  aaaa_record_not_proxied: { title: "AAAA record is not proxied (origin IP exposed)", category: "DNS" },
  a_record_dangling: { title: "A record points to an IP that no longer serves you (dangling)", category: "DNS" },
  tls_version_old: { title: "Hostname accepts old TLS versions", category: "TLS & HTTPS" },
  hsts_not_enabled: { title: "HSTS not enabled", category: "TLS & HTTPS", covers: "TLS-004" },
  always_https_not_enabled: { title: "Always Use HTTPS not enabled", category: "TLS & HTTPS", covers: "TLS-003" },
  security_txt_not_enabled: { title: "No security.txt published", category: "Platform" },
  no_challenge_ai_bots: { title: "AI Labyrinth / AI bot challenge not enabled", category: "WAF & bots", covers: "WAF-005" },
  manage_bot_fight_mode: { title: "Bot Fight Mode not enabled", category: "WAF & bots", covers: "WAF-004" },
  standard_super_bot_fight_mode: { title: "Super Bot Fight Mode not configured", category: "WAF & bots", covers: "WAF-004" },
  mfa_not_enabled: { title: "Member without two-factor authentication", category: "Identity & access", covers: "IAM-001" },
  skip_above_threshold: { title: "Over 30% of security rules use Skip", category: "WAF & bots" },
  spf: { title: "SPF problem", category: "Email", covers: "EML-001" },
  dmarc: { title: "DMARC problem", category: "Email", covers: "EML-002" },
  dkim: { title: "DKIM problem", category: "Email" },
  waf_not_enabled: { title: "Managed WAF not enabled", category: "WAF & bots", covers: "WAF-001" },
};

export const SC_SEVERITY: Record<string, Severity> = { Critical: "critical", Moderate: "medium", Low: "low" };
