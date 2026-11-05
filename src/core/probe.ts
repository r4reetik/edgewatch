// Subdomain-takeover confirmation. For your own hostnames whose CNAME points at a
// provider known to allow takeovers, send one plain GET and compare the reply with
// that provider's "this resource doesn't exist" page. Limits: 100 hosts, 8 at a
// time, 8s timeout, 64 KB read, no cookies, redirects only within the same host.

import { pool } from "./cloudflare.ts";
import { isHostRecord } from "./dns-util.ts";
import type { TakeoverProbe, ZoneInventory } from "./types.ts";
import { readFileSync } from "node:fs";

const MAX_HOSTS = 100;
const MAX_BYTES = 64 * 1024;
const TIMEOUT_MS = 8000;
/** Identifies the probe to whoever runs the host, with a link to the project (package.json homepage). */
const USER_AGENT = `Edgewatch takeover check (+${String(JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")).homepage || "").replace(/#.*$/, "")})`;

interface Fingerprint {
  provider: string;
  target: RegExp;
  body: RegExp;
  /** Providers that now make you prove domain ownership before attaching it: a match means "likely", not "confirmed". */
  verified?: boolean;
}

// Each fingerprint requires both the CNAME target and the response to match, which keeps false positives rare.
export const FINGERPRINTS: Fingerprint[] = [
  { provider: "Amazon S3", target: /\.s3[.-]([a-z0-9-]+\.)?amazonaws\.com$|\.s3-website[.-]/, body: /NoSuchBucket|The specified bucket does not exist/ },
  { provider: "Alibaba Cloud OSS", target: /\.oss-[a-z0-9-]+\.aliyuncs\.com$/, body: /NoSuchBucket|The specified bucket does not exist/ },
  {
    provider: "Google Cloud Storage",
    target: /^c\.storage\.googleapis\.com$|\.storage\.googleapis\.com$/,
    body: /NoSuchBucket|The specified bucket does not exist/,
  },
  { provider: "GitHub Pages", target: /\.github\.io$/, body: /There isn't a GitHub Pages site here/ },
  { provider: "Heroku", target: /\.herokuapp\.com$|\.herokudns\.com$/, body: /no-such-app|There's nothing here, yet|herokucdn\.com\/error-pages\/no-such-app/ },
  {
    provider: "Vercel",
    target: /vercel-dns(-\d+)?\.com$|\.vercel\.app$|cname\.vercel-dns\.com$/,
    body: /DEPLOYMENT_NOT_FOUND|The deployment could not be found/,
    verified: true,
  },
  { provider: "Netlify", target: /\.netlify\.(app|com)$/, body: /Not Found - Request ID/, verified: true },
  {
    provider: "Azure",
    target: /\.(azurewebsites\.net|cloudapp\.net|cloudapp\.azure\.com|trafficmanager\.net|blob\.core\.windows\.net|azureedge\.net)$/,
    body: /404 Web Site not found|Azure Web App - Error 404|The resource you are looking for has been removed|BlobNotFound|ResourceNotFound/,
  },
  { provider: "Shopify", target: /\.myshopify\.com$|shops\.myshopify\.com$/, body: /Sorry, this shop is currently unavailable|Only one step left/ },
  { provider: "Fastly", target: /\.fastly\.net$|fastlylb\.net$/, body: /Fastly error: unknown domain/, verified: true },
  { provider: "Surge", target: /\.surge\.sh$/, body: /project not found/ },
  { provider: "Ghost", target: /\.ghost\.io$/, body: /The thing you were looking for is no longer here, or never was/ },
  { provider: "Zendesk", target: /\.zendesk\.com$/, body: /Help Center Closed/ },
  { provider: "ReadMe", target: /\.readme\.io$/, body: /Project doesnt exist\.\.\. yet!/ },
  { provider: "Bitbucket", target: /\.bitbucket\.io$/, body: /Repository not found/ },
  { provider: "Pantheon", target: /\.pantheonsite\.io$/, body: /404 error unknown site!/ },
];

export function takeoverCandidates(zones: ZoneInventory[]): { host: string; target: string }[] {
  const out: { host: string; target: string }[] = [];
  for (const z of zones)
    for (const r of z.dns) {
      if (r.type !== "CNAME" || !isHostRecord(r)) continue;
      const target = String(r.content).toLowerCase().replace(/\.$/, "");
      if (FINGERPRINTS.some((f) => f.target.test(target))) out.push({ host: String(r.name).toLowerCase(), target });
    }
  return out.slice(0, MAX_HOSTS);
}

export async function probeTakeovers(targets: { host: string; target: string }[]): Promise<TakeoverProbe[]> {
  return pool(targets, 8, async ({ host, target }) => {
    const fps = FINGERPRINTS.filter((f) => f.target.test(target));
    const reply = (await fetchSnippet(`https://${host}/`)) ?? (await fetchSnippet(`http://${host}/`));
    if (!reply) return { host, target, provider: fps[0]?.provider ?? null, status: null, unclaimed: false, match: null };
    for (const f of fps) {
      const m = reply.body.match(f.body);
      if (m) return { host, target, provider: f.provider, status: reply.status, unclaimed: true, match: m[0], verifiedProvider: !!f.verified };
    }
    return { host, target, provider: fps[0]?.provider ?? null, status: reply.status, unclaimed: false, match: null };
  });
}

async function fetchSnippet(url: string, hops = 0): Promise<{ status: number; body: string } | null> {
  try {
    const res = await fetch(url, {
      redirect: "manual",
      headers: { "user-agent": USER_AGENT, accept: "text/html,*/*" },
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const loc = res.headers.get("location");
    if (res.status >= 300 && res.status < 400 && loc && hops < 2) {
      const next = new URL(loc, url);
      if (next.hostname === new URL(url).hostname) return fetchSnippet(next.href, hops + 1);
      return { status: res.status, body: "" };
    }
    if (!res.body) return { status: res.status, body: "" };
    const reader = res.body.getReader();
    let body = "",
      bytes = 0;
    const dec = new TextDecoder();
    while (bytes < MAX_BYTES) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.length;
      body += dec.decode(value, { stream: true });
    }
    await reader.cancel().catch(() => {});
    return { status: res.status, body };
  } catch {
    return null;
  }
}
