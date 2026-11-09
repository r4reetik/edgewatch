// Domains and certificates on Vercel: registrations about to lapse, project
// domains that were never verified, and custom certificates near expiry.

import { defineChecks } from "./define.ts";
import { DAY_MS } from "../../../shared/time.ts";

const RENEW_WARN_DAYS = 30;
const CERT_WARN_DAYS = 21;
const daysLeft = (t: number, now: number) => Math.floor((t - now) / DAY_MS);
const date = (t: number) => new Date(t).toISOString().slice(0, 10);

export default defineChecks(
  {
    "VDM-001": {
      category: "DNS",
      severity: "high",
      docs: "https://vercel.com/docs/domains/renew-a-domain",
      requires: ["domains"],
      attackPath: true,
      title: "Domain registered through Vercel is about to lapse",
      why: "Auto-renew is off and the registration ends soon. A lapsed domain stops resolving, and anyone can register it afterwards and receive your traffic and email.",
      fix: "Turn on auto-renew for the domain under Domains, or renew it now. Check the payment method on file.",
    },
    "VDM-002": {
      category: "DNS",
      severity: "medium",
      docs: "https://vercel.com/docs/domains/troubleshooting#domain-verification",
      requires: ["projectDomains"],
      title: "Project domain isn't verified",
      why: "Vercel couldn't confirm you own the domain, usually because another team or account uses it. Until it's verified, it doesn't serve this project, and someone else may control it.",
      fix: "Add the TXT record Vercel shows under the project's Settings → Domains, or remove the domain if it isn't yours.",
    },
    "VDM-003": {
      category: "TLS & HTTPS",
      severity: "high",
      docs: "https://vercel.com/docs/domains/custom-SSL-certificate",
      requires: ["certs"],
      title: "Custom certificate is about to expire",
      why: "Vercel renews its own certificates, but not ones you uploaded. When it expires, browsers block the site.",
      fix: "Upload a renewed certificate under Team Settings → Domains → SSL Certificates, or remove the custom one and let Vercel issue its own.",
    },
  },
  ({ inv, d }, report) => {
    for (const dom of inv.domains ?? []) {
      if (!dom.registrar || dom.expiresAt == null) continue;
      const left = daysLeft(dom.expiresAt, inv.now);
      report("VDM-001", {
        resource: dom.name,
        pass: dom.renew !== false || left > RENEW_WARN_DAYS,
        severity: left < 7 ? "critical" : undefined,
        detail: `Expires ${date(dom.expiresAt)} (${left} days), auto-renew ${dom.renew ? "on" : "off"}`,
        link: d.domains,
      });
    }

    for (const p of inv.projects)
      for (const x of p.domains ?? [])
        report("VDM-002", {
          zone: p.name,
          resource: x.name,
          pass: x.verified,
          detail: x.verified ? "" : `Added to ${p.name}, not verified`,
          link: d.project(p.name, "domains"),
        });

    for (const c of inv.certs ?? []) {
      if (c.autoRenew || c.expiresAt == null) continue;
      const left = daysLeft(c.expiresAt, inv.now);
      report("VDM-003", {
        resource: c.names[0] ?? c.id,
        pass: left > CERT_WARN_DAYS,
        severity: left < 0 ? "critical" : undefined,
        detail: left < 0 ? `Expired on ${date(c.expiresAt)}` : `Expires ${date(c.expiresAt)} (${left} days)`,
        evidence: { names: c.names },
        link: d.team("domains"),
      });
    }
  },
);
