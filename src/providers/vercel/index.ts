// Vercel as a provider: teams (or a personal account) scanned with a Vercel access token.

import { VercelClient } from "./client.ts";
import { collectVercel } from "./inventory.ts";
import { evaluateVercel } from "./engine.ts";
import { VERCEL_CHECKS } from "./catalog.ts";
import { listVercelAccounts, probeVercel, teamOf, verifyVercelToken } from "./permissions.ts";
import { projectRows, vercelLinks } from "./views.ts";
import { PROVIDER_INFO } from "../../shared/providers.ts";
import type { Provider } from "../types.ts";

export const vercel: Provider = {
  info: PROVIDER_INFO.vercel,
  checks: VERCEL_CHECKS.map((c) => ({ ...c, provider: "vercel" as const })),
  tokenHelp: () => ({ url: "https://vercel.com/account/settings/tokens", templateUrl: null }),
  verify: (token) => verifyVercelToken(token),
  listAccounts: listVercelAccounts,
  probe: probeVercel,
  async scan({ token, account, engine, onProgress }) {
    const client = new VercelClient(token, teamOf(account.id));
    try {
      const inv = await collectVercel(client, onProgress);
      // A personal account's ID is its user ID, which the inventory reads back; keep the stored one for fingerprints.
      inv.accountId = account.id;
      onProgress({ phase: "Evaluating checks" });
      const evaluation = evaluateVercel(inv, engine);
      const failures = evaluation.findings.filter((f) => !f.pass);
      return {
        accountName: inv.accountName,
        evaluation,
        snapshot: { projects: projectRows(inv, failures), links: vercelLinks(inv) },
        coverage: [...client.coverage.values()].map((c) =>
          c.ok ? c : { ...c, skippedChecks: VERCEL_CHECKS.filter((ch) => ch.requires?.includes(c.key)).map((ch) => ch.id) },
        ),
        calls: client.calls,
      };
    } catch (e) {
      throw Object.assign(e as Error, { calls: client.calls });
    }
  },
  ownedDomains: (snap) => [...new Set((snap.links?.vercelDomains ?? []).map((d) => d.host))],
};
