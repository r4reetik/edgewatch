// AWS as a provider: one account per access key, scanned with signed GET requests
// only. Give the key's user AWS's managed SecurityAudit policy; nothing more.

import { collectAws } from "./inventory.ts";
import { evaluateAws } from "./engine.ts";
import { AWS_CHECKS } from "./catalog.ts";
import { clientFor, listAwsAccounts, probeAws, verifyAwsKey } from "./permissions.ts";
import { addressHistory, awsLinks, hostedDomains, ownAddresses, regionRows } from "./views.ts";
import { PROVIDER_INFO } from "../../shared/providers.ts";
import type { Provider } from "../types.ts";

export const aws: Provider = {
  info: PROVIDER_INFO.aws,
  checks: AWS_CHECKS.map((c) => ({ ...c, provider: "aws" as const })),
  tokenHelp: () => ({ url: "https://console.aws.amazon.com/iam/home#/users/create", templateUrl: null }),
  verify: (token) => verifyAwsKey(token),
  listAccounts: listAwsAccounts,
  probe: probeAws,
  async scan({ token, account, engine, previous, onProgress }) {
    const client = clientFor(token, account.id);
    try {
      const inv = await collectAws(client, onProgress);
      if (inv.accountId !== account.id)
        throw new Error(`This access key belongs to AWS account ${inv.accountId}, not ${account.id}. Replace it on the Accounts page.`);
      // Addresses the account held at its last complete scan and doesn't now were released: DNS that still points at them is dangling.
      // Scans from before this history existed only stored the addresses they shared, which is the same list.
      const before = previous?.addressHistory ?? (previous?.links?.awsAddresses ? { held: previous.links.awsAddresses, released: [] } : null);
      const history = addressHistory(before, inv.skippedRegions.length ? null : ownAddresses(inv), inv.now);
      inv.released = history.released;
      onProgress({ phase: "Evaluating checks" });
      const evaluation = evaluateAws(inv, engine);
      const failures = evaluation.findings.filter((f) => !f.pass);
      return {
        accountName: inv.accountName,
        evaluation,
        snapshot: { regions: regionRows(inv, failures), links: awsLinks(inv), ownedDomains: hostedDomains(inv), addressHistory: history },
        coverage: [...client.coverage.values()].map((c) =>
          c.ok ? c : { ...c, skippedChecks: AWS_CHECKS.filter((ch) => ch.requires?.includes(c.key)).map((ch) => ch.id) },
        ),
        calls: client.calls,
      };
    } catch (e) {
      throw Object.assign(e as Error, { calls: client.calls });
    }
  },
  ownedDomains: (snap) => snap.ownedDomains ?? [],
};
