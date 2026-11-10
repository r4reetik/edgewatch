// A check that needs Cloudflare: an AWS load balancer or instance that a
// Cloudflare-proxied hostname sends its traffic to. Cloudflare's WAF, rate limits
// and bot rules only help if the origin refuses everyone else. It reads the DNS
// records of the entity's Cloudflare accounts from their latest scans, and is
// skipped when the entity has none.

import { defineChecks, opensWeb } from "./define.ts";
import type { AwsSecurityGroup } from "../types.ts";

const hostList = (hosts: string[]) => `${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? ` and ${hosts.length - 3} more` : ""}`;

export default defineChecks(
  {
    "XP-006": {
      spans: ["cloudflare"],
      category: "WAF & bots",
      severity: "high",
      docs: "https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/",
      requires: ["loadBalancers", "securityGroups", "networkInterfaces"],
      attackPath: true,
      title: "Origin behind Cloudflare accepts traffic from the whole internet",
      why: "Visitors reach this origin through Cloudflare, where your WAF, rate limits and bot rules run. Its security group also lets anyone connect to it directly, and origin addresses are easy to find (certificate logs, old DNS records, internet scans). An attacker who connects directly skips every Cloudflare protection and can flood the origin itself.",
      fix: "1. In the security group, replace 0.0.0.0/0 on ports 80 and 443 with Cloudflare's address ranges (cloudflare.com/ips); a managed prefix list keeps them in one place. 2. Or connect the origin through Cloudflare Tunnel and remove the inbound rule altogether. 3. Turn on Authenticated Origin Pulls in Cloudflare so the origin can refuse requests that didn't come through your zone.",
    },
  },
  ({ inv, d, related }, report) => {
    if (!related.toAws && !related.dnsAddresses) return;
    const viaName = new Map<string, string[]>();
    for (const r of related.toAws ?? []) if (r.proxied && r.kind === "elb") viaName.set(r.name, [...(viaName.get(r.name) ?? []), r.host]);
    const viaIp = new Map<string, string[]>();
    for (const r of related.dnsAddresses ?? []) if (r.proxied) viaIp.set(r.ip, [...(viaIp.get(r.ip) ?? []), r.host]);

    for (const region of inv.regions) {
      if (!region.securityGroups || !region.loadBalancers || !region.interfaces) continue;
      const groupsOf = (ids: string[]) => region.securityGroups!.filter((g) => ids.includes(g.id));
      const judge = (resource: string, hosts: string[], groups: AwsSecurityGroup[], what: string, link: string) => {
        const open = groups.filter(opensWeb);
        report("XP-006", {
          zone: region.name,
          resource,
          pass: !open.length,
          detail: open.length
            ? `${hostList(hosts)} ${hosts.length === 1 ? "is" : "are"} proxied through Cloudflare to this ${what}, and ${open.map((g) => g.name).join(", ")} allows web traffic from anywhere`
            : "",
          evidence: open.length
            ? {
                chain: [
                  ...hosts.slice(0, 5).map((h) => ({ label: "Proxied through Cloudflare", value: h })),
                  { label: "Origin", value: `${what} ${resource} in ${region.name}` },
                  ...open.map((g) => ({ label: "Security group", value: `${g.name} (${g.id}) allows ports 80 or 443 from 0.0.0.0/0 or ::/0` })),
                ],
              }
            : null,
          link,
        });
      };

      for (const lb of region.loadBalancers) {
        const hosts = viaName.get(lb.dnsName);
        // A load balancer without groups of its own (a network load balancer) is judged through its targets' addresses below.
        if (hosts && lb.securityGroups.length) judge(lb.name, hosts, groupsOf(lb.securityGroups), "load balancer", d.loadBalancers(region.name));
      }
      for (const i of region.interfaces) {
        const hosts = i.publicIp ? viaIp.get(i.publicIp) : undefined;
        if (!hosts) continue;
        const inst = i.kind === "instance" ? region.instances?.find((x) => x.id === i.owner) : undefined;
        const resource = inst ? (inst.name ? `${inst.name} (${inst.id})` : inst.id) : `${i.kind} ${i.id}`;
        judge(
          resource,
          hosts,
          groupsOf(i.securityGroups),
          i.kind,
          inst ? d.instance(region.name, inst.id) : d.securityGroup(region.name, i.securityGroups[0] ?? ""),
        );
      }
    }
  },
);
