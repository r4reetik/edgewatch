// DNS lookups (over DoH) that the deeper checks need: MX host addresses,
// delegated-subdomain health, DKIM key strength, DMARC report authorization and
// MTA-STS. Every lookup is a public DNS query, never a connection to the host.

import { doh, pool, type DohAnswer } from "./cloudflare.ts";
import type { DeepDns, ZoneInventory } from "./types.ts";

const TYPE_TXT = 16,
  TYPE_A = 1,
  TYPE_AAAA = 28;
const unquote = (s: string): string => String(s).replace(/^"|"$/g, "").replace(/"\s*"/g, "");
const txtOf = (r: DohAnswer) => r.answers.filter((a) => a.type === TYPE_TXT).map((a) => unquote(a.data));

export async function deepDns(zones: ZoneInventory[]): Promise<DeepDns> {
  const lower = (s: string) => String(s).toLowerCase().replace(/\.$/, "");
  const mxHosts = new Set<string>(),
    delegated = new Map<string, string[]>(),
    dkimNames = new Set<string>();
  const ruaPairs = new Set<string>(),
    mailDomains = new Set<string>();

  for (const z of zones) {
    const zone = z.name.toLowerCase();
    for (const r of z.dns) {
      const name = lower(r.name);
      if (r.type === "MX") {
        mxHosts.add(lower(r.content));
        if (name === zone) mailDomains.add(zone);
      }
      if (r.type === "NS" && name !== zone) delegated.set(name, [...(delegated.get(name) || []), lower(r.content)]);
      if ((r.type === "TXT" || r.type === "CNAME") && /\._domainkey\./.test(name) && !name.startsWith("*")) dkimNames.add(name);
      if (r.type === "TXT" && name.startsWith("_dmarc.")) {
        const v = unquote(r.content);
        const rua = v.match(/rua=([^;]+)/i)?.[1] || "";
        for (const addr of rua.split(",")) {
          const dom = addr
            .trim()
            .replace(/^mailto:/i, "")
            .split("@")[1]
            ?.toLowerCase()
            .replace(/!.*$/, "");
          const owner = name.slice("_dmarc.".length);
          if (dom && dom !== owner && !dom.endsWith(`.${zone}`) && dom !== zone) ruaPairs.add(`${owner}|${dom}`);
        }
      }
    }
  }

  const [mx, deleg, dkim, auth, sts] = await Promise.all([
    pool([...mxHosts], 10, async (h) => {
      const [a, aaaa] = await Promise.all([doh(h, "A"), doh(h, "AAAA")]);
      return [h, [...a.answers, ...aaaa.answers].filter((x) => x.type === TYPE_A || x.type === TYPE_AAAA).map((x) => x.data)] as const;
    }),
    pool([...delegated.entries()], 5, async ([name, ns]) => [name, await delegationHealth(name, ns)] as const),
    pool([...dkimNames], 10, async (n) => [n, parseDkim(txtOf(await doh(n, "TXT")).find((t) => /p=/i.test(t)) || null)] as const),
    pool([...ruaPairs], 10, async (pair) => {
      const [owner, dom] = pair.split("|");
      return [pair, txtOf(await doh(`${owner}._report._dmarc.${dom}`, "TXT")).some((t) => /^v=DMARC1/i.test(t))] as const;
    }),
    pool([...mailDomains], 10, async (d) => [d, txtOf(await doh(`_mta-sts.${d}`, "TXT")).some((t) => /^v=STSv1/i.test(t))] as const),
  ]);

  return {
    mxAddresses: Object.fromEntries(mx),
    delegations: Object.fromEntries(deleg),
    dkim: Object.fromEntries(dkim),
    dmarcAuth: Object.fromEntries(auth),
    mtaSts: Object.fromEntries(sts),
  };
}

/** A delegation is lame when the delegated nameservers don't serve the name, or don't exist. */
async function delegationHealth(name: string, ns: string[]): Promise<DeepDns["delegations"][string]> {
  const nsLookups = await Promise.all(ns.map((h) => doh(h, "A")));
  const missing = ns.filter((_, i) => nsLookups[i].status === 3);
  if (missing.length === ns.length) return { ns, status: "unresolvable", detail: `None of the nameservers exist: ${missing.join(", ")}.` };
  const soa = await doh(name, "SOA");
  // 2 = SERVFAIL, 5 = REFUSED: the delegated servers don't serve this name.
  if (soa.status === 2 || soa.status === 5)
    return { ns, status: "lame", detail: `Delegated nameservers answer ${soa.status === 2 ? "SERVFAIL" : "REFUSED"} for ${name}.` };
  return { ns, status: "ok", detail: "" };
}

/** Key type and approximate RSA modulus size from a DKIM record's base64 public key. */
export function parseDkim(record: string | null): DeepDns["dkim"][string] {
  if (!record) return null;
  const tags = Object.fromEntries(
    record
      .split(";")
      .map((t) => t.trim().split("="))
      .filter((t) => t[0])
      .map(([k, ...v]) => [k.toLowerCase(), v.join("=").trim()]),
  );
  const type = (tags.k || "rsa").toLowerCase();
  const p = (tags.p || "").replace(/\s+/g, "");
  if (!p) return { bits: null, type, revoked: true };
  if (type !== "rsa") return { bits: null, type, revoked: false };
  // SubjectPublicKeyInfo DER: about 38 bytes of framing, the rest is the modulus and exponent.
  const der = Math.floor((p.length * 3) / 4) - (p.endsWith("==") ? 2 : p.endsWith("=") ? 1 : 0);
  const bits = der < 100 ? 512 : der < 200 ? 1024 : der < 330 ? 2048 : der < 460 ? 3072 : 4096;
  return { bits, type, revoked: false };
}
