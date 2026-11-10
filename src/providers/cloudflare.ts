// Cloudflare as a provider: a thin adapter over src/core, where the Cloudflare
// client, inventory, checks and views live (they predate providers).

import { CloudflareClient } from "../core/cloudflare.ts";
import { collectInventory } from "../core/inventory.ts";
import { evaluate } from "../core/engine.ts";
import { CHECKS } from "../core/catalog.ts";
import { listAccounts, probePermissions, tokenTemplateUrl, verifyToken } from "../core/permissions.ts";
import { activityView, valueView, zoneGrid } from "../core/views.ts";
import { cloudflareLinks } from "../core/links.ts";
import { fetchEc2Prefixes } from "../core/aws-ranges.ts";
import { PROVIDER_INFO } from "../shared/providers.ts";
import type { Provider } from "./types.ts";

export const cloudflare: Provider = {
  info: PROVIDER_INFO.cloudflare,
  checks: CHECKS.map((c) => ({ ...c, provider: "cloudflare" as const })),
  tokenHelp: (accountId) => ({ url: "https://dash.cloudflare.com/profile/api-tokens", templateUrl: tokenTemplateUrl(accountId) }),
  verify: (token, accountIds) => verifyToken(token, accountIds[0] || null),
  listAccounts,
  probe: probePermissions,
  async scan({ token, account, engine, probeTakeovers, onProgress }) {
    const cf = new CloudflareClient(token, account.id);
    try {
      const inv = await collectInventory(cf, onProgress, { probeTakeovers });
      // Only with AWS accounts in the entity: AWS's public address ranges, to recognise records that point at AWS.
      // If the file can't be read the check that needs it is skipped.
      if (engine.related?.awsAddresses) inv.awsPrefixes = await fetchEc2Prefixes().catch(() => null);
      onProgress({ phase: "Evaluating checks" });
      const evaluation = evaluate(inv, engine);
      const failures = evaluation.findings.filter((f) => f.source === "custom");
      return {
        accountName: inv.accountName,
        evaluation,
        snapshot: {
          zones: zoneGrid(inv, failures),
          value: valueView(inv),
          activity: activityView(inv),
          securityCenter: evaluation.securityCenter,
          probes: { takeover: inv.takeover ? { probed: inv.takeover.length, unclaimed: inv.takeover.filter((p) => p.unclaimed).length } : null },
          links: cloudflareLinks(inv),
        },
        coverage: [...cf.coverage.values()].map((c) =>
          c.ok ? c : { ...c, skippedChecks: CHECKS.filter((ch) => ch.requires?.includes(c.key)).map((ch) => ch.id) },
        ),
        calls: cf.calls,
      };
    } catch (e) {
      throw Object.assign(e as Error, { calls: cf.calls });
    }
  },
  ownedDomains: (snap) => (snap.zones || []).map((z) => z.name),
};
