// Cost & usage: paid plans on zones that barely see traffic.

import { defineChecks } from "./define.ts";

const LOW_TRAFFIC = 100_000;

export default defineChecks(
  {
    "COST-001": {
      category: "Cost & usage",
      severity: "low",
      docs: "https://developers.cloudflare.com/fundamentals/subscriptions-and-billing/",
      requires: ["traffic"],
      title: "Paid plan on a zone with very little traffic",
      why: "Paid-plan features only pay off on zones that serve real traffic.",
      fix: "Consider moving the zone to the Free plan, or start using the paid features you are paying for.",
    },
  },
  ({ inv, d }, report) => {
    for (const z of inv.zones) {
      if (z.plan === "free") continue;
      const t = inv.traffic?.[z.id];
      if (!t) continue;
      report("COST-001", {
        zone: z.name,
        resource: z.name,
        pass: t.requests >= LOW_TRAFFIC,
        link: d.zone(z.name),
        detail: `${t.requests.toLocaleString("en-US")} requests in 30 days on ${z.planName}${z.planPrice ? ` ($${z.planPrice}/month)` : ""}.`,
      });
    }
  },
);
