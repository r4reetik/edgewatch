// Checks that need AWS: Cloudflare DNS records that name an AWS endpoint (a
// CloudFront distribution, a load balancer, an S3 bucket) or point at an AWS
// address. They compare them with what the entity's AWS accounts have, from their
// latest scans, and are skipped when the entity has no AWS account, or one whose
// endpoints or addresses couldn't all be read.

import { defineChecks } from "./define.ts";
import { awsEndpointOf, DANGLING } from "../links.ts";
import { inPrefixes } from "../aws-ranges.ts";

export default defineChecks(
  {
    "XP-004": {
      spans: ["aws"],
      category: "DNS",
      severity: "high",
      docs: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html",
      requires: ["dnsRecords"],
      attackPath: true,
      title: "DNS record points at an AWS resource that no AWS account in the entity has",
      why: "The record names a CloudFront distribution, load balancer or S3 bucket that none of the entity's AWS accounts has. A missing bucket or CloudFront alias can be claimed by anyone, who then serves content under your hostname. A missing load balancer can't be claimed (its name is random), so that record is dead, or points into an AWS account Edgewatch doesn't see.",
      fix: "1. If the site moved or was retired, delete the DNS record in Cloudflare. 2. If it should be live, recreate the resource or point the record at the current one. 3. If the resource belongs to an AWS account that isn't in Edgewatch, add that account to this entity, or mark the finding as a false positive.",
    },
    "XP-007": {
      spans: ["aws"],
      category: "DNS",
      severity: "high",
      docs: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html",
      requires: ["dnsRecords"],
      attackPath: true,
      title: "DNS record points at an AWS address the entity released",
      why: "Edgewatch saw this address in one of the entity's AWS accounts on an earlier scan, and it is gone now: the instance was stopped or deleted, or the Elastic IP was released. AWS hands released addresses to other customers, and whoever gets this one receives your hostname's traffic, through Cloudflare's proxy too, and can obtain a certificate for it.",
      fix: "1. If the server is gone, delete the DNS record in Cloudflare. 2. If it moved, point the record at its current address, and give the server an Elastic IP so the address can't change again. 3. If the address moved to an AWS account that isn't in Edgewatch, add that account to this entity.",
    },
    "XP-008": {
      spans: ["aws"],
      category: "DNS",
      severity: "low",
      docs: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html",
      requires: ["dnsRecords"],
      title: "DNS record points at an AWS address outside the entity's accounts",
      why: "The address is in AWS's EC2 range, but none of the entity's AWS accounts holds it. It may be a vendor's server or an AWS account of yours that Edgewatch doesn't scan. It may also be an address you released before Edgewatch started watching, which AWS has since given to someone else.",
      fix: "1. Find out who runs the server at that address. 2. If it is an AWS account of yours, add it to this entity so its addresses are tracked. 3. If it is a vendor's, mark the finding as accepted. 4. If nobody knows, delete the record.",
    },
  },
  ({ inv, opts, d }, report) => {
    const addresses = opts.related?.awsAddresses;
    if (addresses) {
      const held = new Set(addresses);
      const released = new Map((opts.related?.awsReleased ?? []).map((r) => [r.ip, r.at]));
      for (const z of inv.zones) {
        if (!z.dnsReadable) continue;
        for (const r of z.dns) {
          if (r.type !== "A") continue;
          const host = r.name.toLowerCase();
          const found = held.has(r.content);
          const gone = released.get(r.content);
          const link = d.zone(z.name, "dns/records");
          // Only what is known is reported: an address the entity holds passes, one it was seen to release fails.
          if (found || gone)
            report("XP-007", {
              zone: z.name,
              resource: host,
              pass: found,
              detail: found ? "" : `A ${r.content}${r.proxied ? " (proxied)" : ""}, which left this entity's AWS accounts on ${gone!.slice(0, 10)}`,
              evidence: found
                ? null
                : {
                    chain: [
                      { label: "Cloudflare DNS", value: `${host} A ${r.content}${r.proxied ? ", proxied" : ""}` },
                      { label: "Last held", value: `Edgewatch saw ${r.content} in the entity's AWS accounts until ${gone!.slice(0, 10)}` },
                      { label: "Now", value: `${held.size} addresses checked, none is ${r.content}` },
                    ],
                  },
              link,
            });
          if (inv.awsPrefixes && !gone && inPrefixes(r.content, inv.awsPrefixes))
            report("XP-008", {
              zone: z.name,
              resource: host,
              pass: found,
              detail: found ? "" : `A ${r.content}${r.proxied ? " (proxied)" : ""}, an AWS address that isn't in this entity's AWS accounts`,
              link,
            });
        }
      }
    }

    const endpoints = opts.related?.awsEndpoints;
    if (!endpoints) return;
    const have = new Set(endpoints.map((e) => `${e.kind}:${e.name}`));
    for (const z of inv.zones) {
      if (!z.dnsReadable) continue;
      for (const r of z.dns) {
        const aws = r.type === "CNAME" ? awsEndpointOf(r.content) : null;
        if (!aws) continue;
        const host = r.name.toLowerCase();
        const found = have.has(`${aws.kind}:${aws.name}`);
        const kind = DANGLING[aws.kind];
        report("XP-004", {
          zone: z.name,
          resource: host,
          pass: found,
          severity: found ? undefined : kind.severity,
          detail: found ? "" : `CNAME ${r.content}, a ${kind.what} that isn't in this entity's AWS accounts. ${kind.risk}`,
          confidence: found ? undefined : "likely",
          evidence: found
            ? null
            : {
                chain: [
                  { label: "Cloudflare DNS", value: `${host} CNAME ${r.content}` },
                  { label: `${kind.what[0].toUpperCase()}${kind.what.slice(1)}s in this entity's AWS accounts`, value: `None is ${aws.name}` },
                ],
              },
          link: d.zone(z.name, "dns/records"),
        });
      }
    }
  },
);
