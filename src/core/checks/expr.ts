// Just enough of Cloudflare's Rules language to reason about rules: which hosts
// a rule targets, which IP ranges and networks it trusts, and which request
// fields it keys on. Not a full parser: it reads the common, documented forms.

/** Hostnames a rule targets through `http.host eq "x"` or `http.host in {"a" "b"}`. */
export function hostsIn(expr: string): string[] {
  const out = new Set<string>();
  for (const m of expr.matchAll(/http\.host\s+(?:eq|==)\s+"([^"]+)"/g)) out.add(m[1].toLowerCase());
  for (const m of expr.matchAll(/http\.host\s+in\s+\{([^}]*)\}/g)) {
    for (const h of m[1].matchAll(/"([^"]+)"/g)) out.add(h[1].toLowerCase());
  }
  return [...out];
}

/** CIDR blocks and single addresses in `ip.src` conditions. */
export function cidrsIn(expr: string): string[] {
  const out: string[] = [];
  for (const m of expr.matchAll(/ip\.src\s+(?:in\s+\{([^}]*)\}|(?:eq|==)\s+([0-9a-f.:/]+))/gi)) {
    const body = m[1] ?? m[2] ?? "";
    for (const t of body.split(/\s+/)) if (/^[0-9a-f.:]+(\/\d+)?$/i.test(t) && /[.:]/.test(t)) out.push(t);
  }
  return out;
}

/** Prefix length of a CIDR (an address without one is a single host). */
export function prefixLength(cidr: string): number {
  const [addr, len] = cidr.split("/");
  if (len) return Number(len);
  return addr.includes(":") ? 128 : 32;
}

/** True when the rule trusts a whole network: an ASN, or an IPv4 range wider than /16 (IPv6 wider than /32). */
export function broadNetwork(expr: string): string | null {
  const asn = expr.match(/ip\.(?:geoip\.)?(?:src\.)?asnum\s+(?:in\s+\{[^}]*\}|(?:eq|==)\s+\d+)/);
  if (asn) return asn[0];
  const wide = cidrsIn(expr).find((c) => (c.includes(":") ? prefixLength(c) < 32 : prefixLength(c) < 16));
  return wide ?? null;
}

// Fields the client controls completely.
const SPOOFABLE = [
  ["http.user_agent", "User-Agent"],
  ["http.request.headers", "a request header"],
  ["http.cookie", "a cookie"],
  ["http.request.cookies", "a cookie"],
  ["http.referer", "the Referer"],
  ["http.request.uri.query", "the query string"],
  ["http.request.uri.args", "a query parameter"],
  ["http.request.body", "the request body"],
] as const;

// Conditions an attacker can't forge from an arbitrary client.
const TRUSTED =
  /ip\.src|cf\.client\.bot|cf\.verified_bot_category|cf\.bot_management\.verified_bot|cf\.tls_client_auth\.cert_verified|cf\.edge\.server_port|\$[a-z0-9_]+/;

/** The forgeable inputs a rule relies on, when it relies on nothing an attacker can't set. */
export function spoofableOnly(expr: string): string[] | null {
  if (TRUSTED.test(expr)) return null;
  const used = [...new Set(SPOOFABLE.filter(([f]) => expr.includes(f)).map(([, label]) => label))];
  return used.length ? used : null;
}

/** IPv4 address in CIDR? (IPv6 compared as exact strings.) */
export function ipInCidr(ip: string, cidr: string): boolean {
  if (ip.includes(":") || cidr.includes(":")) return ip.toLowerCase() === cidr.split("/")[0].toLowerCase();
  const [base, lenStr] = cidr.split("/");
  const len = lenStr ? Number(lenStr) : 32;
  const toInt = (a: string) => a.split(".").reduce((n, o) => (n << 8) + Number(o), 0) >>> 0;
  const mask = len === 0 ? 0 : (~0 << (32 - len)) >>> 0;
  return (toInt(ip) & mask) === (toInt(base) & mask);
}
