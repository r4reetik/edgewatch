// AWS's published address ranges (ip-ranges.amazonaws.com), reduced to the EC2
// ranges: the public addresses of instances, Elastic IPs, NAT gateways and
// network load balancers. Used to tell "this DNS record points at an AWS address"
// from "this record points somewhere else", for the dangling-address checks. It is
// a public file: no credential is sent, and it is only read when an AWS account
// is connected.

/** Inclusive [start, end] of IPv4 ranges as integers, sorted by start. */
export type Prefixes = [number, number][];

export const AWS_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json";

export function ipToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.some((p) => p > 255) ? null : ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

export function toPrefixes(cidrs: string[]): Prefixes {
  const out: Prefixes = [];
  for (const c of cidrs) {
    const [ip, bits] = c.split("/");
    const start = ipToInt(ip ?? "");
    const n = Number(bits);
    if (start == null || !Number.isInteger(n) || n < 0 || n > 32) continue;
    const size = n === 0 ? 2 ** 32 : 2 ** (32 - n);
    const base = Math.floor(start / size) * size;
    out.push([base, base + size - 1]);
  }
  return out.sort((a, b) => a[0] - b[0]);
}

export function inPrefixes(ip: string, prefixes: Prefixes): boolean {
  const n = ipToInt(ip);
  if (n == null) return false;
  // Ranges can nest, so walk back from the last one that starts at or before the address.
  let lo = 0;
  let hi = prefixes.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (prefixes[mid][0] <= n) lo = mid;
    else hi = mid - 1;
  }
  for (let i = lo; i >= 0 && i > lo - 64; i--) if (prefixes[i][0] <= n && n <= prefixes[i][1]) return true;
  return false;
}

/** GET the published ranges and keep EC2's IPv4 ones. Throws when the file can't be read. */
export async function fetchEc2Prefixes(): Promise<Prefixes> {
  const res = await fetch(AWS_RANGES_URL, { method: "GET", signal: AbortSignal.timeout(30_000), headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`AWS address ranges answered ${res.status}`);
  const body = (await res.json()) as { prefixes?: { ip_prefix?: string; service?: string }[] };
  return toPrefixes((body.prefixes ?? []).filter((p) => p.service === "EC2" && p.ip_prefix).map((p) => p.ip_prefix!));
}
