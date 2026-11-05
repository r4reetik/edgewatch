// TLS & HTTPS: encryption modes, protocol versions, HSTS and every kind of
// certificate. Edge settings only matter on zones that proxy traffic.

import { defineChecks } from "./define.ts";
import { daysUntil, parseDate, proxiedZone } from "./helpers.ts";
import { OLD_TLS } from "../cf-constants.ts";
import type { ExpiringCertificate } from "../cf-types.ts";
import type { Severity } from "../types.ts";

const SIX_MONTHS = 15_768_000;
const EDGE_CERT_WARN_DAYS = 14;
const CERT_WARN_DAYS = 30;
const BAD_CERT_STATUS = /timed_out|validation_timed_out|issuance_timed_out/;
/** Cipher suites considered weak: CBC mode with SHA-1, plain RSA key exchange, 3DES. */
const WEAK_CIPHER = /(-CBC|DES-CBC3|^AES\d+-SHA|^AES\d+-GCM|-SHA$)/i;
const SSL_DOCS = "https://developers.cloudflare.com/ssl";

export default defineChecks(
  {
    "TLS-001": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes/full-strict/",
      requires: ["zoneSettings"],
      title: "SSL/TLS mode is not Full (strict)",
      why: "Flexible sends traffic to your origin unencrypted; Full encrypts but doesn't verify the origin certificate, so it can be intercepted.",
      fix: "Install a valid or Cloudflare Origin CA certificate on origins, then set SSL/TLS → Overview to Full (strict).",
    },
    "TLS-002": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/minimum-tls/",
      requires: ["zoneSettings"],
      title: "Minimum TLS version below 1.2",
      why: "TLS 1.0 and 1.1 have known weaknesses and are deprecated by browsers and PCI DSS.",
      fix: "Set SSL/TLS → Edge Certificates → Minimum TLS Version to 1.2.",
    },
    "TLS-003": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/always-use-https/",
      requires: ["zoneSettings"],
      title: "Always Use HTTPS is off",
      why: "Visitors who type http:// stay on an unencrypted connection.",
      fix: "Turn on SSL/TLS → Edge Certificates → Always Use HTTPS.",
    },
    "TLS-004": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/http-strict-transport-security/",
      requires: ["zoneSettings"],
      title: "HSTS is not enabled",
      why: "Without HSTS a network attacker can downgrade a visitor's first request to HTTP.",
      fix: "Enable HSTS under SSL/TLS → Edge Certificates once every hostname serves HTTPS. Start with a short max-age.",
    },
    "TLS-005": {
      category: "TLS & HTTPS",
      severity: "low",
      docs: "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/http-strict-transport-security/",
      requires: ["zoneSettings"],
      title: "HSTS max-age is under 6 months",
      why: "A short max-age expires quickly, so returning visitors lose downgrade protection.",
      fix: "Raise HSTS max-age to at least 6 months (15768000 seconds).",
    },
    "TLS-006": {
      category: "TLS & HTTPS",
      severity: "low",
      docs: "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/tls-13/",
      requires: ["zoneSettings"],
      title: "TLS 1.3 is disabled",
      why: "TLS 1.3 is faster and removes legacy cipher suites.",
      fix: "Turn on SSL/TLS → Edge Certificates → TLS 1.3.",
    },
    "TLS-007": {
      category: "TLS & HTTPS",
      severity: "low",
      docs: "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/automatic-https-rewrites/",
      requires: ["zoneSettings"],
      title: "Automatic HTTPS Rewrites is off",
      why: "Pages that reference http:// assets trigger mixed-content warnings or load insecurely.",
      fix: "Turn on SSL/TLS → Edge Certificates → Automatic HTTPS Rewrites.",
    },
    "TLS-008": {
      category: "TLS & HTTPS",
      severity: "high",
      docs: "https://developers.cloudflare.com/ssl/edge-certificates/",
      requires: ["certificates"],
      title: "Edge certificate inactive or expiring within 14 days",
      why: "Visitors get certificate errors when the edge certificate lapses.",
      fix: "Check the certificate pack under SSL/TLS → Edge Certificates; fix the validation records or order a replacement.",
    },
    "TLS-009": {
      category: "TLS & HTTPS",
      severity: "low",
      docs: "https://developers.cloudflare.com/speed/optimization/protocol/0-rtt-connection-resumption/",
      requires: ["zoneSettings"],
      title: "0-RTT connection resumption is on",
      why: "0-RTT early data can be replayed by an attacker, which is unsafe for non-idempotent requests.",
      fix: "Turn off Speed → Optimization → 0-RTT unless you have confirmed your app tolerates replays.",
    },
    "TLS-010": {
      category: "TLS & HTTPS",
      severity: "high",
      docs: "https://developers.cloudflare.com/ssl/edge-certificates/additional-options/total-tls/",
      requires: ["certificates", "dnsRecords"],
      title: "Proxied hostname has no matching edge certificate",
      why: "Universal SSL covers the apex and one level of subdomains. Deeper names like a.b.example.com get a certificate error in every browser.",
      fix: "Order an Advanced certificate for the hostname (or turn on Total TLS), or move it up one level.",
    },
    "TLS-011": {
      category: "TLS & HTTPS",
      severity: "high",
      docs: "https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/",
      requires: ["originCertificates"],
      title: "Origin CA certificate expires soon",
      why: "When the certificate on your origin expires, Cloudflare's connection to it fails under Full (strict) and visitors see 526 errors.",
      fix: "Create a new Origin CA certificate under SSL/TLS → Origin Server and install it on the origin before the date.",
    },
    "TLS-012": {
      category: "TLS & HTTPS",
      severity: "low",
      docs: `${SSL_DOCS}/edge-certificates/additional-options/cipher-suites/recommendations/`,
      requires: ["zoneSettings"],
      title: "Legacy cipher suites are allowed",
      why: "The default (Legacy) list still accepts CBC ciphers with SHA-1 and plain RSA key exchange, which PCI DSS and most audits flag.",
      fix: "Set SSL/TLS → Edge Certificates → Cipher suites to the Modern or Compatible profile.",
    },
    "TLS-013": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: `${SSL_DOCS}/edge-certificates/additional-options/minimum-tls/`,
      requires: ["tlsSettings"],
      title: "A hostname allows older TLS than the rest of the zone",
      why: "Per-hostname TLS settings override the zone's minimum, so this hostname still accepts TLS 1.0 or 1.1.",
      fix: "Remove the per-hostname minimum TLS override, or raise it to 1.2.",
    },
    "TLS-014": {
      category: "TLS & HTTPS",
      severity: "high",
      docs: `${SSL_DOCS}/edge-certificates/custom-certificates/renewing/`,
      requires: ["tlsSettings", "originCertificates", "mtlsCertificates"],
      title: "Uploaded certificate expired or expiring within 30 days",
      why: "Custom edge certificates, client certificates and mTLS or origin-pull certificates don't renew on their own. When they lapse, visitors, devices or origins start failing TLS.",
      fix: "Upload a renewed certificate before the expiry date, then remove the old one.",
    },
    "TLS-015": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: `${SSL_DOCS}/edge-certificates/universal-ssl/disable-universal-ssl/`,
      requires: ["tlsSettings", "certificates"],
      title: "Universal SSL is off and no other certificate covers the zone",
      why: "Proxied hostnames get a certificate error for every visitor.",
      fix: "Turn Universal SSL back on under SSL/TLS → Edge Certificates, or order an Advanced certificate that covers the zone's hostnames.",
    },
  },
  ({ inv, d }, report) => {
    const expiring = (zone: string | null, label: string, c: ExpiringCertificate, link: string) => {
      const exp = parseDate(c.expires_on);
      if (exp == null || /deleted|inactive/.test(String(c.status || ""))) return;
      const days = daysUntil(exp, inv.now);
      const names = (c.hosts || c.hostnames || [c.common_name || c.name || c.id]).filter(Boolean).slice(0, 3).join(", ");
      report("TLS-014", {
        zone,
        resource: `${label}: ${names}`,
        pass: days > CERT_WARN_DAYS,
        link,
        detail:
          days < 0
            ? `${label} for ${names} expired ${-days} days ago (${new Date(exp).toISOString().slice(0, 10)}).`
            : `${label} for ${names} expires in ${days} days (${new Date(exp).toISOString().slice(0, 10)}).`,
      });
    };
    for (const c of inv.mtlsCertificates || []) expiring(null, "mTLS certificate", c, `${d.accountConfig}/mtls`);

    for (const z of inv.zones) {
      if (!z.settings || !proxiedZone(z)) continue;
      const s = z.settings,
        zone = z.name;
      const ssl = d.zone(zone, "ssl-tls"),
        edgeCerts = d.zone(zone, "ssl-tls/edge-certificates");

      const sslSev = ({ off: "critical", flexible: "high", full: "medium" } as Record<string, Severity>)[String(s.ssl)];
      report("TLS-001", { zone, resource: zone, pass: s.ssl === "strict", severity: sslSev, detail: `SSL/TLS mode is "${s.ssl}".`, link: ssl });
      report("TLS-002", {
        zone,
        resource: zone,
        pass: !OLD_TLS.includes(String(s.min_tls_version)),
        detail: `Minimum TLS version is ${s.min_tls_version}.`,
        link: edgeCerts,
      });
      report("TLS-003", { zone, resource: zone, pass: s.always_use_https === "on", link: edgeCerts });
      const hsts = s.security_header?.strict_transport_security;
      report("TLS-004", { zone, resource: zone, pass: !!hsts?.enabled, link: edgeCerts });
      if (hsts?.enabled) {
        const age = Number(hsts.max_age || 0);
        report("TLS-005", {
          zone,
          resource: zone,
          pass: age >= SIX_MONTHS,
          detail: `max-age is ${age} seconds (${Math.round(age / 86400)} days).`,
          link: edgeCerts,
        });
      }
      report("TLS-006", { zone, resource: zone, pass: s.tls_1_3 !== "off", link: edgeCerts });
      report("TLS-007", { zone, resource: zone, pass: s.automatic_https_rewrites === "on", link: edgeCerts });
      report("TLS-009", { zone, resource: zone, pass: s["0rtt"] !== "on", link: d.zone(zone, "speed/optimization") });

      if (z.plan === "business" || z.plan === "enterprise") {
        const ciphers = s.ciphers || [];
        const weak = ciphers.filter((c) => WEAK_CIPHER.test(c));
        report("TLS-012", {
          zone,
          resource: zone,
          pass: ciphers.length > 0 && weak.length === 0,
          link: edgeCerts,
          detail: ciphers.length
            ? `Allowed cipher suites include ${weak.slice(0, 4).join(", ")}${weak.length > 4 ? ` and ${weak.length - 4} more` : ""}.`
            : "The zone uses Cloudflare's default (Legacy) cipher suites.",
        });
      }
      for (const h of z.hostnameMinTls || []) {
        report("TLS-013", {
          zone,
          resource: h.hostname,
          pass: !OLD_TLS.includes(String(h.value)),
          link: edgeCerts,
          detail: `${h.hostname} accepts TLS ${h.value} while the zone's minimum is ${s.min_tls_version}.`,
        });
      }

      for (const p of z.certPacks || []) {
        if (/deleted|deletion|deactivat|inactive|expired|cleanup/.test(p.status)) continue;
        const expiries = (p.certificates || []).map((c) => Date.parse(c.expires_on)).filter(Boolean);
        const soonest = expiries.length ? Math.min(...expiries) : null;
        const days = soonest ? daysUntil(soonest, inv.now) : null;
        const bad = BAD_CERT_STATUS.test(p.status) || (p.status === "active" && days != null && days < EDGE_CERT_WARN_DAYS);
        report("TLS-008", {
          zone,
          resource: `${p.type} cert: ${(p.hosts || []).slice(0, 3).join(", ")}`,
          pass: !bad,
          link: edgeCerts,
          detail: `Status ${p.status}${days != null ? `, expires in ${days} days` : ""}.`,
        });
      }

      // TLS-010: proxied names no active certificate covers. Universal SSL stops one level below the apex;
      // Total TLS issues a certificate for every proxied name, and custom certificates add their own hosts.
      if (z.certPacks && !z.totalTls?.enabled) {
        const hosts = [
          ...z.certPacks.filter((p) => p.status === "active").flatMap((p) => p.hosts || []),
          ...(z.customCerts || []).flatMap((c) => c.hosts || []),
        ].map((h) => h.toLowerCase());
        const coveredBy = (n: string) =>
          hosts.some((h) => h === n || (h.startsWith("*.") && n.endsWith(h.slice(1)) && !n.slice(0, -(h.length - 1)).includes(".")));
        const names = new Set(z.dns.filter((r) => r.proxied && ["A", "AAAA", "CNAME"].includes(r.type)).map((r) => r.name.toLowerCase()));
        for (const n of names) {
          report("TLS-010", {
            zone,
            resource: n,
            pass: coveredBy(n),
            link: edgeCerts,
            detail: `${n} is proxied, but none of the zone's active certificates (${[...new Set(hosts)].slice(0, 6).join(", ")}) cover it, so browsers show a certificate error.`,
          });
        }
      }
      if (z.universalSsl && z.certPacks) {
        const others = z.certPacks.some((p) => p.status === "active" && p.type !== "universal") || (z.customCerts || []).length > 0;
        report("TLS-015", {
          zone,
          resource: zone,
          pass: z.universalSsl.enabled !== false || others,
          link: edgeCerts,
          detail: "Universal SSL is turned off and the zone has no other active certificate.",
        });
      }

      for (const c of z.originCerts || []) {
        const exp = parseDate(c.expires_on);
        if (exp == null) continue;
        const days = daysUntil(exp, inv.now);
        report("TLS-011", {
          zone,
          resource: `Origin CA: ${(c.hostnames || []).slice(0, 3).join(", ")}`,
          pass: days > CERT_WARN_DAYS,
          link: d.zone(zone, "ssl-tls/origin"),
          detail:
            days < 0
              ? `Expired ${-days} days ago (${new Date(exp).toISOString().slice(0, 10)}).`
              : `Expires in ${days} days (${new Date(exp).toISOString().slice(0, 10)}).`,
        });
      }
      for (const c of z.customCerts || []) expiring(zone, "Custom certificate", c, edgeCerts);
      for (const c of z.clientCerts || []) if (c.status === "active") expiring(zone, "Client certificate", c, d.zone(zone, "ssl-tls/client-certificates"));
      for (const c of z.aopHostnames || []) expiring(zone, "Origin-pull certificate", c, d.zone(zone, "ssl-tls/origin"));
    }
  },
);
