// Checks that need Vercel: Cloudflare DNS records that send traffic to Vercel.
// XP-001 compares them with the domains the entity's Vercel projects serve (from
// the latest scan of the entity's Vercel accounts) and is skipped when the entity
// has none. XP-002 needs only the record itself.

import { defineChecks } from "./define.ts";
import { pointsAtVercel } from "../links.ts";

export default defineChecks(
  {
    "XP-001": {
      category: "DNS",
      severity: "high",
      docs: "https://vercel.com/docs/domains/working-with-domains/add-a-domain",
      requires: ["dnsRecords"],
      attackPath: true,
      title: "DNS record points at Vercel, but no Vercel project in the entity serves it",
      why: "The record sends visitors to Vercel, yet none of the entity's Vercel projects has this hostname. Whoever adds it to their own Vercel project first serves your traffic under your domain.",
      fix: "1. If the site moved or was retired, delete the DNS record in Cloudflare. 2. If it should be live, add the hostname to the right Vercel project under Settings → Domains. 3. If it belongs to a Vercel team that isn't in Edgewatch, add that team to this entity, or mark the finding as a false positive.",
    },
    "XP-002": {
      category: "Platform",
      severity: "low",
      docs: "https://vercel.com/guides/cloudflare-with-vercel",
      requires: ["dnsRecords"],
      title: "Vercel site is proxied through Cloudflare",
      why: "With Cloudflare's proxy in front, Vercel's firewall, bot protection and rate limits only see Cloudflare's addresses, and Vercel can fail to renew the site's certificate. Two caches can also serve different versions.",
      fix: "Set the record to DNS only (grey cloud) and use Vercel's firewall, or, if you keep Cloudflare in front on purpose, mark this as accepted and protect the *.vercel.app URLs with Standard Protection in Vercel.",
    },
  },
  ({ inv, opts, d }, report) => {
    const served = opts.related?.vercelDomains;
    const known = served ? new Map(served.map((x) => [x.host, x])) : null;
    for (const z of inv.zones) {
      if (!z.dnsReadable) continue;
      for (const r of z.dns) {
        if (!pointsAtVercel(r.type, r.content)) continue;
        const host = r.name.toLowerCase();
        const link = d.zone(z.name, "dns/records");
        if (known) {
          const match = known.get(host) ?? known.get(`*.${host.split(".").slice(1).join(".")}`);
          report("XP-001", {
            zone: z.name,
            resource: host,
            pass: !!match,
            detail: match ? `Served by Vercel project ${match.project}` : `${r.type} ${r.content}, not on any Vercel project in this entity`,
            confidence: match ? undefined : "likely",
            evidence: match
              ? null
              : {
                  chain: [
                    { label: "Cloudflare DNS", value: `${host} ${r.type} ${r.content}` },
                    { label: "Vercel projects in this entity", value: `${new Set(served!.map((x) => x.project)).size} checked, none has ${host}` },
                  ],
                },
            link,
          });
        }
        report("XP-002", { zone: z.name, resource: host, pass: !r.proxied, detail: r.proxied ? `${r.type} ${r.content}, proxied` : "", link });
      }
    }
  },
);
