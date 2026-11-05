// DNS hygiene: dangling and stale records, private addresses, DNSSEC, CAA, and
// load balancers that hand out origin addresses.

import { defineChecks } from "./define.ts";
import { isHostRecord } from "../dns-util.ts";
import { TUNNEL_CNAME } from "../cf-constants.ts";
import { groupBy } from "../../shared/collections.ts";
import { DAY_MS } from "../../shared/time.ts";
import type { Tunnel } from "../cf-types.ts";

const TAKEOVER_PRONE =
  /(amazonaws\.com|cloudfront\.net|elasticbeanstalk\.com|azurewebsites\.net|azureedge\.net|cloudapp\.(net|azure\.com)|trafficmanager\.net|blob\.core\.windows\.net|herokuapp\.com|herokudns\.com|github\.io|vercel|netlify|aliyuncs\.com|storage\.googleapis\.com|appspot\.com|firebaseapp\.com|web\.app|pages\.dev|workers\.dev|fly\.dev|railway\.app|onrender\.com|myshopify\.com|wpengine\.com|ghost\.io|zendesk\.com|readme\.io|webflow\.io|surge\.sh|bitbucket\.io)\.?$/i;
const PRIVATE_V4 = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/;
const PRIVATE_V6 = /^(fc|fd|fe80|::1$)/i;
const _MAIL_FROM_LABEL = /^(send|rsend|bounce|bounces|mail-from|mailfrom|em\d+|mta)\./i;

export default defineChecks(
  {
    "DNS-001": {
      category: "DNS",
      severity: "high",
      docs: "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/routing-to-tunnel/dns/",
      requires: ["dnsRecords", "tunnels"],
      title: "Hostname routes to a deleted Cloudflare Tunnel",
      why: "Requests already fail with error 530; the record is dead weight and confuses incident response.",
      fix: "Delete the DNS record, or point it at the tunnel that replaced it.",
    },
    "DNS-002": {
      category: "DNS",
      severity: "high",
      docs: "https://developers.cloudflare.com/dns/manage-dns-records/troubleshooting/",
      requires: ["dnsRecords", "doh"],
      title: "CNAME target does not exist (dangling record)",
      why: "If the target is a cloud resource (bucket, app, load balancer) someone else can claim it and serve content on your hostname.",
      fix: "Delete the record or point it at a live target. Treat cloud-provider targets as urgent.",
    },
    "DNS-003": {
      category: "DNS",
      severity: "medium",
      docs: "https://developers.cloudflare.com/dns/manage-dns-records/",
      requires: ["dnsRecords"],
      title: "Private IP address published in public DNS",
      why: "Leaks internal network layout and can enable DNS-rebinding attacks.",
      fix: "Move internal names to a private zone or resolver, or remove them.",
    },
    "DNS-004": {
      category: "DNS",
      severity: "medium",
      docs: "https://developers.cloudflare.com/dns/manage-dns-records/troubleshooting/records-with-same-name/",
      requires: ["dnsRecords"],
      title: "CNAME shares a name with other records",
      why: "A CNAME must be the only record at its name (RFC 1034). Resolvers may return either record set, which breaks mail or verification unpredictably.",
      fix: "Move the other records to a different name, or replace the CNAME with A/AAAA records.",
    },
    "DNS-005": {
      category: "DNS",
      severity: "low",
      docs: "https://developers.cloudflare.com/dns/manage-dns-records/",
      requires: ["dnsRecords", "dnsAnalytics"],
      title: "Record had no lookups in 30 days",
      why: "Unused records accumulate, get forgotten, and become takeover targets when the infrastructure behind them is released.",
      fix: "Confirm with the owner and delete. Counts are sampled, so zero means under roughly 20–30 lookups.",
    },
    "DNS-006": {
      category: "DNS",
      severity: "medium",
      docs: "https://developers.cloudflare.com/dns/dnssec/",
      requires: ["dnssec"],
      title: "DNSSEC is disabled",
      why: "Without DNSSEC, resolvers can be fed forged answers for your domain (cache poisoning).",
      fix: "Enable DNSSEC under DNS → Settings and add the DS record at your registrar.",
    },
    "DNS-007": {
      category: "DNS",
      severity: "low",
      docs: "https://developers.cloudflare.com/ssl/edge-certificates/caa-records/",
      requires: ["dnsRecords"],
      title: "No CAA records",
      why: "Any certificate authority may issue certificates for this domain.",
      fix: "Add CAA records for the CAs you use (Cloudflare's universal SSL CAs plus any others, e.g. Let's Encrypt, Amazon).",
    },
    "DNS-008": {
      category: "DNS",
      severity: "low",
      docs: "https://developers.cloudflare.com/dns/manage-dns-records/reference/wildcard-dns-records/",
      requires: ["dnsRecords"],
      title: "DNS-only wildcard record",
      why: "Every possible subdomain resolves straight to the origin, unprotected by Cloudflare and invisible to inventory.",
      fix: "Prefer explicit records; if the wildcard is needed, proxy it or restrict what the origin serves.",
    },
    "DNS-009": {
      category: "DNS",
      severity: "high",
      docs: "https://developers.cloudflare.com/load-balancing/understand-basics/proxy-modes/",
      requires: ["loadBalancers", "lbPools"],
      attackPath: true,
      title: "DNS-only load balancer publishes its origin addresses",
      why: "A load balancer that isn't proxied answers DNS queries with the origins' real IP addresses, so anyone can bypass Cloudflare and attack them directly.",
      fix: "Turn on Proxied for the load balancer under Traffic → Load Balancing, unless it serves non-HTTP traffic that needs DNS-only mode.",
    },
  },
  ({ inv, d }, report) => {
    const activeTunnels = new Set((inv.tunnels || []).map((t) => t.id));
    const deleted: Record<string, Tunnel> = Object.fromEntries((inv.deletedTunnels || []).map((t) => [t.id, t]));
    const pools = new Map((inv.lbPools || []).map((p) => [p.id, p]));

    for (const z of inv.zones) {
      if (!z.dnsReadable) continue;
      const zone = z.name;
      const link = d.zone(zone, "dns/records");
      const byName = groupBy(z.dns, (r) => r.name.toLowerCase());

      for (const r of z.dns) {
        const name = r.name.toLowerCase();
        const res = `${r.name} ${r.type}`;
        const target = r.content.toLowerCase().replace(/\.$/, "");

        if (r.type === "CNAME") {
          const tunnel = target.match(TUNNEL_CNAME);
          if (tunnel) {
            const t = deleted[tunnel[1]];
            report("DNS-001", {
              zone,
              resource: res,
              pass: activeTunnels.has(tunnel[1]),
              link,
              detail: t ? `Tunnel "${t.name}" was deleted on ${t.deleted_at?.slice(0, 10)}.` : `Tunnel ${tunnel[1]} does not exist in this account.`,
            });
          } else if (isHostRecord(r)) {
            if (!/^[a-z0-9._-]+$/.test(target)) {
              report("DNS-002", {
                zone,
                resource: res,
                pass: false,
                severity: "medium",
                detail: `"${r.content}" is not a valid hostname, so lookups fail.`,
                link,
              });
            } else {
              const lookup = inv.resolved?.[target];
              if (lookup && lookup.status !== -1) {
                const prone = TAKEOVER_PRONE.test(target);
                report("DNS-002", {
                  zone,
                  resource: res,
                  pass: lookup.status !== 3,
                  severity: prone ? "high" : "medium",
                  link,
                  confidence: "likely",
                  detail: `Target ${r.content} returns NXDOMAIN${prone ? " and is a cloud-provider name that could be claimed by someone else" : ""}.${r.proxied ? " Record is proxied." : ""}`,
                });
              }
            }
          }
        }

        if (r.type === "A" || r.type === "AAAA") {
          const priv = r.type === "A" ? PRIVATE_V4.test(r.content) : PRIVATE_V6.test(r.content);
          report("DNS-003", { zone, resource: res, pass: !priv, detail: `Points to ${r.content}.`, link });
        }

        // Cloudflare answers proxied and flattened CNAMEs with A/AAAA, so only DNS-only, unflattened ones conflict.
        const flattened = name === zone || z.settings?.cname_flattening === "flatten_all";
        if (r.type === "CNAME" && !r.proxied && !flattened) {
          const others = (byName.get(name) || []).filter((x) => x.type !== "CNAME").map((x) => x.type);
          report("DNS-004", { zone, resource: res, pass: others.length === 0, detail: `Also at this name: ${[...new Set(others)].join(", ")}.`, link });
        }

        if (isHostRecord(r) && z.lookups) {
          const age = inv.now - Date.parse(r.modified_on || r.created_on);
          if (age > 30 * DAY_MS) {
            const n = z.lookups[name] ?? 0;
            report("DNS-005", {
              zone,
              resource: res,
              pass: n > 0,
              detail: `0 lookups in 30 days. Target: ${r.content}${r.proxied ? " (proxied)" : ""}.`,
              link,
              confidence: "likely",
            });
          }
        }

        if (name.startsWith("*") && ["A", "AAAA", "CNAME"].includes(r.type)) {
          report("DNS-008", { zone, resource: res, pass: !!r.proxied, detail: `DNS-only wildcard to ${r.content}.`, link });
        }
      }

      if (z.dnssec) {
        report("DNS-006", {
          zone,
          resource: zone,
          pass: z.dnssec.status === "active",
          link: d.zone(zone, "dns/settings"),
          detail:
            z.dnssec.status === "pending"
              ? "DNSSEC is enabled at Cloudflare but the DS record is not yet at the registrar."
              : `DNSSEC status: ${z.dnssec.status}.`,
        });
      }
      if (z.dns.some(isHostRecord)) {
        report("DNS-007", { zone, resource: zone, pass: z.dns.some((r) => r.type === "CAA"), link });
      }

      for (const lb of z.loadBalancers || []) {
        if (lb.enabled === false) continue;
        const origins = [...(lb.default_pools || []), lb.fallback_pool]
          .filter((p): p is string => !!p)
          .flatMap((id) => pools.get(id)?.origins || [])
          .map((o) => o.address)
          .filter(Boolean);
        report("DNS-009", {
          zone,
          resource: lb.name,
          pass: lb.proxied !== false,
          link: d.zone(zone, "traffic/load-balancing"),
          detail: `${lb.name} is DNS-only, so lookups return ${origins.length ? [...new Set(origins)].slice(0, 4).join(", ") : "its origin addresses"}.`,
          evidence: origins.length
            ? {
                chain: [
                  { label: "Load balancer", value: `${lb.name} (DNS only)` },
                  { label: "Origins handed out", value: [...new Set(origins)].join(", ") },
                ],
              }
            : null,
        });
      }
    }
  },
);
