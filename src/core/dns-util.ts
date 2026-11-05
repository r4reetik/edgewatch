// DNS record helpers shared by the collector, the checks and the probes.

import type { DnsRecord } from "./cf-types.ts";

/** A record that names a host people connect to (not a service record, wildcard or underscore label). */
export const isHostRecord = (r: Pick<DnsRecord, "type" | "name">): boolean =>
  ["A", "AAAA", "CNAME"].includes(r.type) && !r.name.startsWith("_") && !r.name.includes("._") && !r.name.startsWith("*");

/** A TXT value without its quotes; long values split into quoted chunks are joined. */
export const unquote = (s: string): string => String(s).replace(/^"|"$/g, "").replace(/"\s*"/g, "");

/** Lowercase, without the trailing dot. */
export const hostName = (s: string): string => String(s).toLowerCase().replace(/\.$/, "");
