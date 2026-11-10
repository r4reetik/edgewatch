// How DNS records are recognised as pointing at another provider (Vercel, AWS),
// and what a Cloudflare scan shares with the entity's other accounts.

import type { AwsEndpointKind, ProviderLinks } from "../shared/api.ts";
import type { Inventory } from "./types.ts";

/** Vercel's CNAME targets, and the address ranges its A records use. */
const VERCEL_CNAME = /(^|\.)vercel-dns(-\d+)?\.com\.?$|\.vercel\.app\.?$/i;
const VERCEL_A = /^(76\.76\.21\.\d{1,3}|216\.198\.79\.\d{1,3})$/;

export function pointsAtVercel(type: string, content: string): boolean {
  if (type === "CNAME") return VERCEL_CNAME.test(content);
  if (type === "A") return VERCEL_A.test(content);
  return false;
}

/**
 * The AWS endpoint a hostname names, when the name alone says which resource it is: a CloudFront
 * distribution, a load balancer, or an S3 bucket (its website or REST endpoint). `name` is what an
 * AWS scan lists it under: the distribution's domain, the load balancer's DNS name, the bucket.
 */
export function awsEndpointOf(target: string): { kind: AwsEndpointKind; name: string } | null {
  const host = target.toLowerCase().replace(/\.$/, "");
  if (/^[a-z0-9]+\.cloudfront\.net$/.test(host)) return { kind: "cloudfront", name: host };
  if (/\.elb\.amazonaws\.com(\.cn)?$/.test(host)) return { kind: "elb", name: host.replace(/^dualstack\./, "") };
  const bucket = /^(.+)\.s3(-website)?[.-]([a-z0-9-]+\.)?amazonaws\.com$/.exec(host);
  return bucket ? { kind: "s3", name: bucket[1] } : null;
}

/**
 * What a record that points at a missing AWS endpoint really risks, by kind. A bucket name or a CloudFront
 * alias can be claimed by anyone; a load balancer's name carries a random number, so it can't.
 */
export const DANGLING: Record<AwsEndpointKind, { what: string; severity: "high" | "low"; risk: string }> = {
  s3: { what: "S3 bucket", severity: "high", risk: "Anyone can create a bucket with that name and serve content under this hostname." },
  cloudfront: { what: "CloudFront distribution", severity: "high", risk: "Anyone can add this hostname to their own distribution and serve content under it." },
  elb: {
    what: "load balancer",
    severity: "low",
    risk: "A load balancer's name can't be reused, so this isn't a takeover: the record is dead, or the load balancer is in an AWS account Edgewatch doesn't scan.",
  },
};

export function cloudflareLinks(inv: Inventory): ProviderLinks {
  const toVercel: NonNullable<ProviderLinks["toVercel"]> = [];
  const toAws: NonNullable<ProviderLinks["toAws"]> = [];
  const dnsAddresses: NonNullable<ProviderLinks["dnsAddresses"]> = [];
  for (const z of inv.zones)
    for (const r of z.dns) {
      const host = r.name.toLowerCase();
      if (pointsAtVercel(r.type, r.content)) toVercel.push({ host, zone: z.name, type: r.type, target: r.content, proxied: !!r.proxied });
      const aws = r.type === "CNAME" ? awsEndpointOf(r.content) : null;
      if (aws) toAws.push({ host, zone: z.name, target: r.content, ...aws, proxied: !!r.proxied });
      if (r.type === "A") dnsAddresses.push({ host, zone: z.name, ip: r.content, proxied: !!r.proxied });
    }
  // Without readable DNS the lists would look empty rather than unknown.
  return inv.zones.every((z) => z.dnsReadable) ? { toVercel, toAws, dnsAddresses } : {};
}
