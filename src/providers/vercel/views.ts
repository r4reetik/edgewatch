// What a Vercel scan stores for the dashboard: one row per project for the
// Projects page, and the domains other providers' checks need.

import { previewProtection, protectsProductionUrls } from "./checks/deployments.ts";
import { countBySeverity } from "../../shared/severity.ts";
import type { ProjectRow, ProviderLinks } from "../../shared/api.ts";
import type { Result } from "../../core/types.ts";
import type { VercelInventory } from "./types.ts";

export function projectRows(inv: VercelInventory, failures: Result[]): ProjectRow[] {
  return inv.projects.map((p) => {
    const preview = previewProtection(p);
    const fw = p.firewall;
    return {
      id: p.id,
      name: p.name,
      framework: p.framework,
      nodeVersion: p.nodeVersion,
      git: p.git ? `${p.git.repo}` : null,
      domains: (p.domains ?? []).filter((d) => !d.redirect).map((d) => d.name),
      previews: preview.length ? preview.join(", ") : "Public",
      productionUrls: protectsProductionUrls(p) ? "Protected" : "Public",
      firewall: fw ? fw.enabled : p.firewallEnabled,
      managedRules: fw
        ? Object.entries(fw.managedRules)
            .filter(([, r]) => r.active && r.action !== "log")
            .map(([k]) => k)
        : null,
      envVars: p.env ? p.env.filter((e) => e.type !== "system").length : null,
      sensitiveEnvVars: p.env ? p.env.filter((e) => e.type === "sensitive").length : null,
      gitForkProtection: p.git ? p.gitForkProtection : null,
      findings: countBySeverity(failures.filter((f) => f.zone === p.name)),
    };
  });
}

/** The domains this team serves, for Cloudflare's checks in the same entity. */
export function vercelLinks(inv: VercelInventory): ProviderLinks {
  const out: NonNullable<ProviderLinks["vercelDomains"]> = [];
  for (const p of inv.projects) {
    if (!p.domains) continue;
    const protectsDeploymentUrls = protectsProductionUrls(p);
    for (const d of p.domains) out.push({ host: d.name.toLowerCase(), project: p.name, projectId: p.id, protectsDeploymentUrls });
  }
  // A project whose domains couldn't be read makes the list incomplete; Cloudflare's checks would call its hosts dangling.
  return inv.projects.every((p) => p.domains) ? { vercelDomains: out } : {};
}
