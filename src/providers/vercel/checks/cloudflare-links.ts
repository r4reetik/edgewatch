// Checks that need Cloudflare: a Vercel project whose custom domain sits behind
// Cloudflare in the same entity. They read the latest scan of the entity's
// Cloudflare accounts, and are skipped when the entity has none.

import { defineChecks } from "./define.ts";
import { protectsProductionUrls } from "./deployments.ts";

export default defineChecks(
  {
    "XP-003": {
      category: "WAF & bots",
      severity: "medium",
      docs: "https://vercel.com/docs/deployment-protection#understanding-deployment-protection-by-environment",
      requires: ["projects", "projectDomains"],
      attackPath: true,
      title: "Cloudflare's protection can be skipped through the *.vercel.app URL",
      why: "The custom domain is proxied through Cloudflare, so Cloudflare's WAF, rate limits and bot rules guard it. The same site also answers on public *.vercel.app deployment URLs, which go straight to Vercel without any of that.",
      fix: "In the Vercel project's Settings → Deployment Protection, choose Standard Protection so only the custom domain is public. Then traffic can only reach the site through Cloudflare.",
    },
  },
  ({ inv, d, related }, report) => {
    if (!related.toVercel) return;
    const proxied = new Map(related.toVercel.filter((r) => r.proxied).map((r) => [r.host.toLowerCase(), r]));
    for (const p of inv.projects) {
      const behind = (p.domains ?? []).filter((x) => proxied.has(x.name.toLowerCase()));
      if (!behind.length) continue;
      const open = !protectsProductionUrls(p);
      report("XP-003", {
        zone: p.name,
        resource: p.name,
        pass: !open,
        detail: open ? `${behind.map((x) => x.name).join(", ")} is proxied through Cloudflare, but the project's *.vercel.app URLs are public` : "",
        confidence: open ? "likely" : undefined,
        evidence: open
          ? {
              chain: [
                ...behind.map((x) => ({ label: "Proxied through Cloudflare", value: `${x.name} (zone ${proxied.get(x.name.toLowerCase())?.zone})` })),
                { label: "Served by Vercel project", value: p.name },
                { label: "Deployment URLs", value: "Public: *.vercel.app answers without Cloudflare" },
              ],
            }
          : null,
        link: d.project(p.name, "deployment-protection"),
      });
    }
  },
);
