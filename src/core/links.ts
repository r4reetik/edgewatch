// How Cloudflare DNS records are recognised as pointing at another provider, and
// what a Cloudflare scan shares with the entity's other accounts.

import type { ProviderLinks } from "../shared/api.ts";
import type { Inventory } from "./types.ts";

/** Vercel's CNAME targets, and the address ranges its A records use. */
const VERCEL_CNAME = /(^|\.)vercel-dns(-\d+)?\.com\.?$|\.vercel\.app\.?$/i;
const VERCEL_A = /^(76\.76\.21\.\d{1,3}|216\.198\.79\.\d{1,3})$/;

export function pointsAtVercel(type: string, content: string): boolean {
  if (type === "CNAME") return VERCEL_CNAME.test(content);
  if (type === "A") return VERCEL_A.test(content);
  return false;
}

export function cloudflareLinks(inv: Inventory): ProviderLinks {
  const toVercel: NonNullable<ProviderLinks["toVercel"]> = [];
  for (const z of inv.zones)
    for (const r of z.dns)
      if (pointsAtVercel(r.type, r.content)) toVercel.push({ host: r.name.toLowerCase(), zone: z.name, type: r.type, target: r.content, proxied: !!r.proxied });
  // Without readable DNS the list would look empty rather than unknown.
  return inv.zones.every((z) => z.dnsReadable) ? { toVercel } : {};
}
