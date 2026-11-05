// Attack surface: findings that come from correlating DNS, SPF, MX, rules,
// tunnels, Access applications and live probes. No single setting shows these.

import { defineChecks } from "./define.ts";
import { zoneOf } from "./helpers.ts";
import { ipInCidr } from "./expr.ts";
import { hostName as host, isHostRecord, unquote } from "../dns-util.ts";
import { TUNNEL_CNAME as TUNNEL } from "../cf-constants.ts";
import type { DnsRecord, IngressRule } from "../cf-types.ts";
import type { Api, EvidenceStep, Inventory, ZoneInventory } from "../types.ts";

/** Spectrum protocols that are remote-administration or file-sharing services. */
const ADMIN_PORTS: Record<string, string> = { "22": "SSH", "23": "Telnet", "3389": "RDP", "445": "SMB", "5900": "VNC", "5985": "WinRM", "5986": "WinRM" };
const txtValue = (r: DnsRecord) => unquote(r.content);
// Targets that are themselves Cloudflare-hosted or authenticated; never a "reachable origin".
const CLOUDFLARE_HOSTED = /(\.workers\.dev|\.pages\.dev|\.r2\.dev|cfargotunnel\.com|\.cloudflare\.com|\.cloudflare\.net)\.?$/i;
// Multi-tenant platforms: the target name isn't a secret origin (anyone can reach the platform with your Host header),
// and Authenticated Origin Pulls can't be enforced there, so origin-exposure checks don't apply.
const MULTI_TENANT =
  /(vercel-dns(-\d+)?\.com|\.vercel\.app|netlify\.(app|com)|\.github\.io|ghs\.googlehosted\.com|\.herokuapp\.com|\.herokudns\.com|\.fly\.dev|\.onrender\.com|\.railway\.app|\.webflow\.(io|com)|\.myshopify\.com|\.squarespace\.com|\.wixdns\.net|\.ghost\.io|\.hubspot(pagebuilder)?\.(com|net)|\.zendesk\.com|\.godaddysites\.com|\.godaddy\.com|\.framer\.(app|website)|\.bubbleapps\.io|\.readme\.io|\.gitbook\.io|\.mintlify\.(app|dev)|\.cloudfront\.net|\.fastly\.net|\.azurefd\.net|\.azureedge\.net|\.b-cdn\.net)\.?$/i;
// Documented placeholder addresses for "originless" proxied records (redirects, Workers).
const ORIGINLESS = /^(100::|192\.0\.2\.\d+)$/;

// Name tokens, by tier. Matching is on whole labels or dash-separated parts.
const ADMIN_TOOLS = new Set([
  "grafana",
  "kibana",
  "jenkins",
  "argocd",
  "argo",
  "vault",
  "phpmyadmin",
  "pma",
  "pgadmin",
  "adminer",
  "prometheus",
  "alertmanager",
  "portainer",
  "rancher",
  "traefik",
  "consul",
  "nomad",
  "airflow",
  "metabase",
  "superset",
  "redash",
  "jupyter",
  "jupyterhub",
  "zabbix",
  "nagios",
  "netdata",
  "keycloak",
  "webmin",
  "cpanel",
  "plesk",
  "kubernetes",
  "k8s",
  "minio",
  "rabbitmq",
  "n8n",
  "retool",
  "sonarqube",
  "admin",
  "administrator",
  "kubeapi",
]);
const INFRA = new Set([
  "jump",
  "bastion",
  "ssh",
  "vpn",
  "db",
  "database",
  "redis",
  "mysql",
  "postgres",
  "postgresql",
  "mongo",
  "mongodb",
  "elasticsearch",
  "elastic",
  "opensearch",
  "kafka",
  "memcached",
  "etcd",
  "internal",
  "intranet",
  "corp",
]);
const PREPROD = new Set(["staging", "stage", "stg", "dev", "uat", "sandbox", "debug"]);

const recordsOf = (inv: Inventory) => inv.zones.flatMap((z) => z.dns.map((r) => ({ z, r })));

/** Access applications covering a whole hostname (path-scoped apps protect only that path). */
function accessHosts(inv: Inventory): { exact: Set<string>; wildcards: string[] } {
  const exact = new Set<string>(),
    wildcards: string[] = [];
  for (const app of inv.accessApps || []) {
    const domains: string[] = [...(app.self_hosted_domains || []), ...(app.destinations || []).map((d: Api) => d.uri).filter(Boolean), app.domain].filter(
      Boolean,
    );
    for (const d of domains) {
      const [h, ...path] = String(d).toLowerCase().split("/");
      const p = path.join("/");
      if (p && p !== "*") continue;
      if (h.startsWith("*.")) wildcards.push(h.slice(1));
      else exact.add(h);
    }
  }
  return { exact, wildcards };
}
const covered = (acc: ReturnType<typeof accessHosts>, h: string) => acc.exact.has(h) || acc.wildcards.some((w) => h.endsWith(w));

/** Is a proxied hostname locked to Cloudflare (Tunnel, Worker, Authenticated Origin Pulls, or an origin-auth header)? */
function originLock(z: ZoneInventory, name: string, target: string): string | null {
  if (TUNNEL.test(target) || CLOUDFLARE_HOSTED.test(target)) return "routed through Cloudflare";
  if (z.aop?.enabled) return "Authenticated Origin Pulls on";
  if ((z.workerRoutes || []).some((r: Api) => routeMatches(String(r.pattern || ""), name) && r.script)) return "served by a Worker";
  if (originAuthHeaderHosts(z).has(name) || originAuthHeaderHosts(z).has("*")) return "origin-auth header set by a transform rule";
  return null;
}

function routeMatches(pattern: string, name: string): boolean {
  const h = pattern.split("/")[0].toLowerCase();
  if (h.startsWith("*")) return name.endsWith(h.slice(1));
  return h === name;
}

/** Hosts that get a static credential header added before reaching the origin. */
export function originAuthHeaderHosts(z: ZoneInventory): Set<string> {
  const out = new Set<string>();
  for (const ph of ["http_request_late_transform", "http_request_transform"]) {
    for (const r of z.phases[ph]?.rules || []) {
      if (r.enabled === false) continue;
      const headers = r.action_parameters?.headers || {};
      const auth = Object.entries(headers).some(([k, v]: [string, Api]) => v?.operation === "set" && /auth|token|secret|key|signature/i.test(k));
      if (!auth) continue;
      const hosts = (String(r.expression).match(/"([a-z0-9.-]+\.[a-z]{2,})"/gi) || []).map((x) => x.replace(/"/g, "").toLowerCase());
      if (hosts.length) hosts.forEach((h) => out.add(h));
      else out.add("*");
    }
  }
  return out;
}

export default defineChecks(
  {
    "ATS-001": {
      category: "Attack surface",
      severity: "high",
      attackPath: true,
      docs: "https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/",
      requires: ["dnsRecords", "doh"],
      title: "Origin IP of a proxied host is exposed",
      why: "Cloudflare only protects traffic that goes through it. Once an attacker knows the origin address, they can attack it directly, around the WAF and DDoS protection.",
      fix: "Move the exposed record behind the proxy or to another address, change the origin IP, and allow only Cloudflare's IP ranges (or a Tunnel) at the origin.",
    },
    "ATS-002": {
      category: "Attack surface",
      severity: "medium",
      docs: "https://developers.cloudflare.com/fundamentals/security/protect-your-origin-server/",
      requires: ["dnsRecords", "originCertificates", "workerRoutes", "otherRulesets"],
      title: "Proxied origins can be reached without Cloudflare",
      why: "Nothing stops someone who finds these origins from connecting to them directly: there's no Tunnel, no Authenticated Origin Pulls and no origin-auth header.",
      fix: "Turn on Authenticated Origin Pulls and require the client certificate at the origin, or move the services behind a Cloudflare Tunnel.",
    },
    "ATS-003": {
      category: "Attack surface",
      severity: "high",
      attackPath: true,
      docs: "https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/self-hosted-public-app/",
      requires: ["dnsRecords", "accessApps"],
      title: "Admin or internal tool reachable without Access",
      why: "Admin consoles and pre-production services exposed to the internet are prime targets, and they are rarely hardened like production.",
      fix: "Put the hostname behind a Cloudflare Access application, or take it off public DNS.",
    },
    "ATS-004": {
      category: "Attack surface",
      severity: "high",
      attackPath: true,
      docs: "https://developers.cloudflare.com/cloudflare-one/applications/non-http/",
      requires: ["tunnelConfigs", "accessApps"],
      title: "Tunnel publishes SSH, RDP or raw TCP without Access",
      why: "Anyone who knows the hostname reaches the service's login prompt through your tunnel.",
      fix: "Create a Cloudflare Access application for the hostname, or route the service privately (WARP) instead of on a public hostname.",
    },
    "ATS-005": {
      category: "Attack surface",
      severity: "low",
      docs: "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/configure-tunnels/origin-configuration/",
      requires: ["tunnelConfigs"],
      title: "Tunnel skips origin TLS verification",
      why: "With noTLSVerify, cloudflared accepts any certificate from the origin, so someone on that network could impersonate the service.",
      fix: "Install a valid certificate on the origin (or set originServerName and caPool), then remove noTLSVerify.",
    },
    "ATS-006": {
      category: "Attack surface",
      severity: "low",
      docs: "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/routing-to-tunnel/",
      requires: ["tunnelConfigs", "dnsRecords"],
      title: "Tunnel routing and DNS disagree",
      why: "Hostnames routed to a tunnel with no matching rule hit its catch-all (usually 404). Routed names without DNS are unreachable configuration.",
      fix: "Add the public hostname to the tunnel's configuration, or remove the stale DNS record or route.",
    },
    "ATS-007": {
      category: "Attack surface",
      severity: "critical",
      attackPath: true,
      docs: "https://developers.cloudflare.com/dns/manage-dns-records/troubleshooting/",
      requires: ["dnsRecords", "takeoverProbes"],
      title: "Subdomain can be taken over",
      why: "The hostname points at a provider resource that no longer exists. Anyone can claim it and serve content, phishing pages or cookies on your domain.",
      fix: "Delete the DNS record now, or recreate the resource at the provider before someone else does.",
    },
    "ATS-008": {
      category: "Attack surface",
      severity: "high",
      attackPath: true,
      docs: "https://developers.cloudflare.com/dns/manage-dns-records/how-to/subdomains-outside-cloudflare/",
      requires: ["dnsRecords", "doh"],
      title: "Delegated subdomain's nameservers don't answer",
      why: "If the nameservers a subdomain is delegated to don't serve it, someone may be able to register the zone at that DNS provider and control the subdomain.",
      fix: "Remove the NS delegation, or fix the zone at the delegated DNS provider.",
    },
    "ATS-009": {
      category: "Attack surface",
      severity: "high",
      docs: "https://developers.cloudflare.com/spectrum/reference/configuration-options/",
      requires: ["spectrum"],
      attackPath: true,
      title: "Spectrum publishes SSH, RDP or another admin protocol to the internet",
      why: "Remote-administration ports behind Spectrum are still open to everyone: Spectrum proxies the connection but doesn't authenticate it.",
      fix: "Put the service behind Access (Cloudflare Tunnel with an Access application, or Access for Infrastructure) and delete the Spectrum application, or at least turn on its IP Access rules.",
    },
  },
  ({ inv, d }, report) => {
    const all = recordsOf(inv);
    const acc = accessHosts(inv);

    // ---- ATS-001 / ATS-002: origin exposure and origin lock
    const dnsOnlyByIp = new Map<string, string[]>(),
      dnsOnlyByTarget = new Map<string, string[]>();
    const spfTerms: { name: string; term: string }[] = [];
    for (const { r } of all) {
      const name = host(r.name);
      if ((r.type === "A" || r.type === "AAAA") && !r.proxied) dnsOnlyByIp.set(r.content, [...(dnsOnlyByIp.get(r.content) || []), name]);
      if (r.type === "CNAME" && !r.proxied) dnsOnlyByTarget.set(host(r.content), [...(dnsOnlyByTarget.get(host(r.content)) || []), name]);
      if (r.type === "TXT" && /^v=spf1/i.test(txtValue(r))) {
        for (const m of txtValue(r).matchAll(/ip[46]:([0-9a-f.:/]+)/gi)) spfTerms.push({ name, term: m[1] });
      }
    }
    const mx = inv.deepDns.mxAddresses;

    for (const z of inv.zones) {
      const unlocked: string[] = [];
      for (const r of z.dns) {
        if (!r.proxied || !isHostRecord(r)) continue;
        const name = host(r.name),
          target = host(r.content);
        if (ORIGINLESS.test(target) || MULTI_TENANT.test(target) || (r.type === "CNAME" && !/^[a-z0-9.-]+$/.test(target))) continue;
        const lock = originLock(z, name, target);
        if (!lock) unlocked.push(name);
        const ips = r.type === "CNAME" ? (inv.resolved[target]?.answers || []).filter((a) => a.type === 1 || a.type === 28).map((a) => a.data) : [r.content];

        const exposures: EvidenceStep[] = [];
        if (r.type === "CNAME" && !TUNNEL.test(target) && !CLOUDFLARE_HOSTED.test(target)) {
          for (const other of dnsOnlyByTarget.get(target) || [])
            if (other !== name) exposures.push({ label: "Same origin, not proxied", value: `${other} is a DNS-only CNAME to ${target}` });
        }
        for (const ip of r.type === "CNAME" ? [] : ips) {
          for (const other of dnsOnlyByIp.get(ip) || [])
            if (other !== name) exposures.push({ label: "Published by a DNS-only record", value: `${other} → ${ip}` });
          for (const t of spfTerms) if (ipInCidr(ip, t.term)) exposures.push({ label: "Listed in SPF", value: `${t.name} allows ${t.term} to send mail` });
          for (const [mxHost, addrs] of Object.entries(mx))
            if (addrs.includes(ip)) exposures.push({ label: "Shared with a mail server", value: `MX host ${mxHost} resolves to ${ip}` });
        }
        if (r.type === "CNAME" && (TUNNEL.test(target) || CLOUDFLARE_HOSTED.test(target))) continue;
        const unique = dedupe(exposures);
        const where =
          unique
            .map((u) => u.value)
            .slice(0, 3)
            .join("; ") + (unique.length > 3 ? `; and ${unique.length - 3} more` : "");
        report("ATS-001", {
          zone: z.name,
          resource: name,
          pass: unique.length === 0,
          severity: lock ? "high" : "critical",
          detail: unique.length
            ? `${name} is proxied, but its origin ${r.type === "CNAME" ? target : ips.join(", ")} is public: ${where}.${lock ? "" : " The origin isn't locked to Cloudflare, so it can be attacked directly."}`
            : "",
          evidence: unique.length
            ? {
                chain: [
                  { label: "Proxied hostname", value: `${name} → ${r.type === "CNAME" ? target : ips.join(", ")}` },
                  ...unique,
                  { label: "Origin lock", value: lock || "None: no Tunnel, Authenticated Origin Pulls or origin-auth header" },
                ],
              }
            : null,
          link: d.zone(z.name, "dns/records"),
        });
      }
      if (z.dns.some((r) => r.proxied)) {
        report("ATS-002", {
          zone: z.name,
          resource: z.name,
          pass: unlocked.length === 0,
          detail: `${unlocked.length} proxied hostname${unlocked.length === 1 ? " reaches" : "s reach"} an origin that accepts connections from anywhere: ${unlocked.slice(0, 6).join(", ")}${unlocked.length > 6 ? `, +${unlocked.length - 6} more` : ""}.`,
          evidence: {
            chain: [
              { label: "Authenticated Origin Pulls", value: z.aop ? (z.aop.enabled ? "On" : "Off for the zone") : "Unknown" },
              { label: "Hostnames not behind a Tunnel or Worker", value: unlocked.slice(0, 20).join(", ") },
            ],
          },
          link: d.zone(z.name, "ssl-tls/origin"),
        });
      }
    }

    // ---- ATS-003: admin and internal tools without Access
    for (const { z, r } of all) {
      if (!isHostRecord(r)) continue;
      const name = host(r.name),
        target = host(r.content);
      const left = name.slice(0, -(z.name.length + 1));
      if (!left) continue;
      // Admin tools must lead or end the first label ("grafana", "grafana-eu", "eu-grafana"); product names
      // that merely contain a word ("ascend-vault-subgraph") don't count.
      const first = left.split(".")[0].split("-");
      const edges = [first[0], first[first.length - 1]];
      const tokens = left.split(/[.-]/);
      // Front ends on multi-tenant hosting are usually deliberately public previews, not internal services.
      const frontEnd = MULTI_TENANT.test(target);
      const tier =
        edges.some((t) => ADMIN_TOOLS.has(t)) && !frontEnd
          ? "high"
          : tokens.some((t) => INFRA.has(t))
            ? "medium"
            : tokens.some((t) => PREPROD.has(t)) && !frontEnd
              ? "low"
              : null;
      if (!tier) continue;
      const token = (tier === "high" ? edges.find((t) => ADMIN_TOOLS.has(t)) : tokens.find((t) => INFRA.has(t) || PREPROD.has(t)))!;
      const isCovered = covered(acc, name);
      report("ATS-003", {
        zone: z.name,
        resource: name,
        pass: isCovered,
        severity: tier,
        detail: `"${token}" suggests ${tier === "high" ? "an admin console" : tier === "medium" ? "internal infrastructure" : "a pre-production environment"}, and no Access application protects ${name}. It ${r.proxied ? "is proxied" : "resolves directly"} to ${r.content}.`,
        evidence: {
          chain: [
            { label: "Name", value: `${name} contains "${token}"` },
            { label: "Reachable", value: `${r.type} ${r.content}${r.proxied ? " (proxied)" : " (DNS only)"}` },
            { label: "Access", value: "No application covers this hostname" },
          ],
        },
        link: d.zt("access/apps"),
        confidence: "likely",
      });
    }

    // ---- ATS-004 / ATS-005 / ATS-006: tunnels
    if (inv.tunnelIngress) {
      const dnsNames = new Set(all.map(({ r }) => host(r.name)));
      const zoneNames = inv.zones.map((z) => z.name.toLowerCase());
      const names: Record<string, string> = Object.fromEntries((inv.tunnels || []).map((t) => [t.id, t.name]));
      for (const [tid, rules] of Object.entries(inv.tunnelIngress) as [string, IngressRule[]][]) {
        const tname = names[tid] || tid;
        const link = d.zt(`networks/tunnels/cfd_tunnel/${tid}/edit`);
        for (const rule of rules) {
          const h = rule.hostname ? host(rule.hostname) : null;
          const service = String(rule.service || "");
          if (!h) continue;
          if (/^(ssh|rdp|tcp|smb):\/\//i.test(service)) {
            report("ATS-004", {
              zone: zoneOf(zoneNames, h),
              resource: h,
              pass: covered(acc, h),
              detail: `Tunnel "${tname}" publishes ${service.split(":")[0].toUpperCase()} at ${h} with no Access application in front.`,
              evidence: {
                chain: [
                  { label: "Tunnel", value: tname },
                  { label: "Route", value: `${h} → ${service}` },
                  { label: "Access", value: "No application covers this hostname" },
                ],
              },
              link,
            });
          }
          if (rule.originRequest?.noTLSVerify) {
            report("ATS-005", {
              zone: zoneOf(zoneNames, h),
              resource: h,
              pass: false,
              detail: `Tunnel "${tname}" connects to ${service} without verifying its certificate.`,
              link,
            });
          }
          if (!h.startsWith("*") && zoneOf(zoneNames, h) && !dnsNames.has(h)) {
            report("ATS-006", {
              zone: zoneOf(zoneNames, h),
              resource: `${h} (route)`,
              pass: false,
              detail: `Tunnel "${tname}" routes ${h} to ${service}, but there's no DNS record for it.`,
              link,
            });
          }
        }
      }
      for (const { z, r } of all) {
        const m = r.type === "CNAME" && String(r.content).match(TUNNEL);
        if (!m || !inv.tunnelIngress[m[1]]) continue;
        const name = host(r.name);
        const routed = inv.tunnelIngress[m[1]].some(
          (rule) => rule.hostname && (host(rule.hostname) === name || (rule.hostname.startsWith("*.") && name.endsWith(host(rule.hostname).slice(1)))),
        );
        report("ATS-006", {
          zone: z.name,
          resource: `${name} (DNS)`,
          pass: routed,
          detail: `${name} points at tunnel "${names[m[1]] || m[1]}", which has no rule for it, so requests hit the catch-all.`,
          link: d.zt(`networks/tunnels/cfd_tunnel/${m[1]}/edit`),
        });
      }
    }

    // ---- ATS-007: confirmed takeovers
    for (const p of inv.takeover || []) {
      const z = inv.zones.find((zz) => p.host === zz.name || p.host.endsWith(`.${zz.name}`));
      report("ATS-007", {
        zone: z?.name ?? null,
        resource: p.host,
        pass: !p.unclaimed,
        detail: `${p.host} points at ${p.target} on ${p.provider}, which answers "${p.match}". The resource behind it no longer exists.`,
        evidence: {
          chain: [
            { label: "DNS", value: `${p.host} CNAME ${p.target}` },
            { label: "Live check", value: `HTTP ${p.status ?? "—"} with "${p.match}"` },
            {
              label: "Provider",
              value: p.verifiedProvider
                ? `${p.provider} asks for domain verification, which may block a takeover`
                : `${p.provider} lets anyone claim this name`,
            },
          ],
        },
        link: z ? d.zone(z.name, "dns/records") : null,
        confidence: p.verifiedProvider ? "likely" : "confirmed",
      });
    }

    // ---- ATS-008: lame delegations
    for (const [name, dlg] of Object.entries(inv.deepDns.delegations)) {
      const z = inv.zones.find((zz) => name.endsWith(`.${zz.name}`));
      report("ATS-008", {
        zone: z?.name ?? null,
        resource: name,
        pass: dlg.status === "ok",
        detail: dlg.detail,
        evidence: {
          chain: [
            { label: "Delegated to", value: dlg.ns.join(", ") },
            { label: "Result", value: dlg.detail },
          ],
        },
        link: z ? d.zone(z.name, "dns/records") : null,
      });
    }

    // ---- ATS-009: Spectrum applications for admin protocols
    for (const z of inv.zones) {
      for (const app of z.spectrum || []) {
        const port =
          String(app.protocol || "")
            .split("/")[1]
            ?.split("-")[0] || "";
        const service = ADMIN_PORTS[port];
        if (!service) continue;
        const name = app.dns?.name || app.id;
        report("ATS-009", {
          zone: z.name,
          resource: `${name} (${app.protocol})`,
          pass: false,
          severity: app.ip_firewall ? "medium" : "high",
          link: d.zone(z.name, "spectrum"),
          detail: `Spectrum publishes ${service} on ${name} (${app.protocol})${app.ip_firewall ? ", limited by IP Access rules" : " to every address on the internet"}.`,
          evidence: {
            chain: [
              { label: "Spectrum app", value: `${name} → ${app.protocol}` },
              { label: "Origin", value: (app.origin_direct || []).join(", ") || "load balancer" },
              { label: "IP firewall", value: app.ip_firewall ? "On" : "Off" },
            ],
          },
        });
      }
      if (
        z.spectrum &&
        !z.spectrum.some(
          (a) =>
            ADMIN_PORTS[
              String(a.protocol || "")
                .split("/")[1]
                ?.split("-")[0] || ""
            ],
        )
      )
        report("ATS-009", { zone: z.name, resource: z.name, pass: true });
    }
  },
);
const dedupe = (steps: EvidenceStep[]) => [...new Map(steps.map((s) => [`${s.label}|${s.value}`, s])).values()];
