// Route 53 records that point at something the entity doesn't have: an AWS
// endpoint (a CloudFront distribution, a load balancer, an S3 bucket), an AWS
// address, or a Vercel address that no Vercel project in the entity serves.
//
// Not every such record can be taken over, and the findings say which: a bucket
// name or a CloudFront alias can be claimed by someone else, an address that
// Edgewatch saw leave the entity's accounts will be handed to another AWS
// customer, but a deleted load balancer's name can't be reused, and an AWS
// address nobody here ever held is most likely someone else's server.

import { defineChecks } from "./define.ts";
import { awsEndpointOf, DANGLING, pointsAtVercel } from "../../../core/links.ts";
import { ownAddresses, ownEndpoints } from "../views.ts";
import { inPrefixes } from "../../../core/aws-ranges.ts";
import { GLOBAL, type AwsRecord } from "../types.ts";

/** An alias to S3's website endpoint doesn't name the bucket: the bucket is the record's own name. */
const S3_WEBSITE = /^s3-website[.-]([a-z0-9-]+\.)?amazonaws\.com$/;

export function endpointOf(r: AwsRecord): { kind: "cloudfront" | "elb" | "s3"; name: string } | null {
  const target = r.targets[0];
  if (!target || (r.type !== "CNAME" && !r.alias)) return null;
  return S3_WEBSITE.test(target) ? { kind: "s3", name: r.name } : awsEndpointOf(target);
}

export default defineChecks(
  {
    "ADN-001": {
      category: "DNS",
      severity: "high",
      docs: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html",
      requires: ["route53", "cloudfront", "s3Buckets", "loadBalancers"],
      attackPath: true,
      title: "Route 53 record points at an AWS resource the entity doesn't have",
      why: "The record names a CloudFront distribution, load balancer or S3 bucket that none of the entity's AWS accounts has. A missing bucket or CloudFront alias can be claimed by anyone, who then serves content under your hostname. A missing load balancer can't be claimed (its name is random), so that record is dead, or points into an AWS account Edgewatch doesn't see.",
      fix: "1. If the site was retired, delete the record in Route 53. 2. If it should be live, recreate the resource or point the record at the current one. 3. If the resource belongs to an AWS account that isn't in Edgewatch, add that account to this entity, or mark the finding as a false positive.",
    },
    "ADN-002": {
      category: "DNS",
      severity: "high",
      docs: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html",
      requires: ["route53", "networkInterfaces"],
      attackPath: true,
      title: "Route 53 record points at an AWS address the entity released",
      why: "Edgewatch saw this address in one of the entity's AWS accounts on an earlier scan, and it is gone now: the instance was stopped or deleted, or the Elastic IP was released. AWS hands released addresses to other customers, and whoever gets this one receives your hostname's traffic and can obtain a certificate for it.",
      fix: "1. If the server is gone, delete the record in Route 53. 2. If it moved, point the record at its current address, and use an Elastic IP or an alias to a load balancer so the address can't change again. 3. If the address moved to an AWS account that isn't in Edgewatch, add that account to this entity.",
    },
    "ADN-003": {
      category: "DNS",
      severity: "low",
      docs: "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html",
      requires: ["route53", "networkInterfaces", "ipRanges"],
      title: "Route 53 record points at an AWS address outside the entity's accounts",
      why: "The address is in AWS's EC2 range, but none of the entity's AWS accounts holds it. It may be a vendor's server or an AWS account of yours that Edgewatch doesn't scan. It may also be an address you released before Edgewatch started watching, which AWS has since given to someone else.",
      fix: "1. Find out who runs the server at that address. 2. If it is an AWS account of yours, add it to this entity so its addresses are tracked. 3. If it is a vendor's, mark the finding as accepted. 4. If nobody knows, delete the record.",
    },
    "XP-005": {
      spans: ["vercel"],
      category: "DNS",
      severity: "high",
      docs: "https://vercel.com/docs/domains/working-with-domains/add-a-domain",
      requires: ["route53"],
      attackPath: true,
      title: "Route 53 record points at Vercel, but no Vercel project in the entity serves it",
      why: "The record sends visitors to Vercel, yet none of the entity's Vercel projects has this hostname. Whoever adds it to their own Vercel project first serves your traffic under your domain.",
      fix: "1. If the site moved or was retired, delete the record in Route 53. 2. If it should be live, add the hostname to the right Vercel project under Settings → Domains. 3. If it belongs to a Vercel team that isn't in Edgewatch, add that team to this entity, or mark the finding as a false positive.",
    },
  },
  ({ inv, d, related }, report) => {
    // Another AWS account in the entity that hasn't shared its list could be the owner: then nothing is judged.
    const own = related.unknown.includes("awsEndpoints") ? null : ownEndpoints(inv);
    const have = own ? new Set([...own, ...(related.awsEndpoints ?? [])].map((e) => `${e.kind}:${e.name}`)) : null;
    const ownIps = related.unknown.includes("awsAddresses") || inv.skippedRegions.length ? null : ownAddresses(inv);
    const held = ownIps ? new Set([...ownIps, ...(related.awsAddresses ?? [])]) : null;
    const released = new Map([...inv.released, ...(related.awsReleased ?? [])].map((r) => [r.ip, r.at]));
    const served = related.vercelDomains ? new Map(related.vercelDomains.map((x) => [x.host, x])) : null;

    for (const z of inv.hostedZones ?? []) {
      for (const r of z.records ?? []) {
        const link = d.hostedZone(z.id);
        const aws = endpointOf(r);
        // A load balancer in a region that refused the scan can't be told from a missing one.
        const unknown = aws?.kind === "elb" && inv.skippedRegions.some((s) => aws.name.includes(`.${s}.`));
        if (aws && have && !unknown) {
          const found = have.has(`${aws.kind}:${aws.name}`);
          const kind = DANGLING[aws.kind];
          report("ADN-001", {
            zone: GLOBAL,
            resource: r.name,
            pass: found,
            severity: found ? undefined : kind.severity,
            detail: found ? "" : `${r.alias ? "Alias" : r.type} to ${r.targets[0]}, a ${kind.what} that isn't in this entity's AWS accounts. ${kind.risk}`,
            confidence: found ? undefined : "likely",
            evidence: found
              ? null
              : {
                  chain: [
                    { label: "Route 53", value: `${r.name} ${r.alias ? "alias" : r.type} ${r.targets[0]} (zone ${z.name})` },
                    { label: `${kind.what[0].toUpperCase()}${kind.what.slice(1)}s in this entity`, value: `None is ${aws.name}` },
                  ],
                },
            link,
          });
        }

        if (held && r.type === "A" && !r.alias)
          for (const ip of r.targets) {
            const found = held.has(ip);
            const gone = released.get(ip);
            // Only what is known is reported: an address the entity holds passes, one it was seen to release fails.
            if (found || gone)
              report("ADN-002", {
                zone: GLOBAL,
                resource: r.name,
                pass: found,
                detail: found ? "" : `A ${ip}, which left this entity's AWS accounts on ${gone!.slice(0, 10)}`,
                evidence: found
                  ? null
                  : {
                      chain: [
                        { label: "Route 53", value: `${r.name} A ${ip} (zone ${z.name})` },
                        { label: "Last held", value: `Edgewatch saw ${ip} in the entity's AWS accounts until ${gone!.slice(0, 10)}` },
                        { label: "Now", value: `${held.size} addresses checked, none is ${ip}` },
                      ],
                    },
                link,
              });
            if (inv.ec2Prefixes && !gone && inPrefixes(ip, inv.ec2Prefixes))
              report("ADN-003", {
                zone: GLOBAL,
                resource: r.name,
                pass: found,
                detail: found ? "" : `A ${ip}, an AWS address that isn't in this entity's AWS accounts`,
                link,
              });
          }

        if (served && !r.alias && r.targets.some((t) => pointsAtVercel(r.type, t))) {
          const match = served.get(r.name) ?? served.get(`*.${r.name.split(".").slice(1).join(".")}`);
          report("XP-005", {
            zone: GLOBAL,
            resource: r.name,
            pass: !!match,
            detail: match ? `Served by Vercel project ${match.project}` : `${r.type} ${r.targets.join(", ")}, not on any Vercel project in this entity`,
            confidence: match ? undefined : "likely",
            evidence: match
              ? null
              : {
                  chain: [
                    { label: "Route 53", value: `${r.name} ${r.type} ${r.targets.join(", ")} (zone ${z.name})` },
                    {
                      label: "Vercel projects in this entity",
                      value: `${new Set(related.vercelDomains!.map((x) => x.project)).size} checked, none has ${r.name}`,
                    },
                  ],
                },
            link,
          });
        }
      }
    }
  },
);
