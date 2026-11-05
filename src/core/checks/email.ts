// Email authentication: SPF, DMARC, DKIM, MTA-STS, DMARC report authorization,
// Email Routing catch-alls, and what DMARC aggregate reports show.

import { defineChecks } from "./define.ts";
import { unquote } from "../dns-util.ts";
import { groupBy } from "../../shared/collections.ts";
import type { DnsRecord } from "../cf-types.ts";

const MAIL_FROM_LABEL = /^(send|rsend|bounce|bounces|mail-from|mailfrom|em\d+|mta)\./i;
const MAX_SPF_LOOKUPS = 10;
/** Unauthenticated messages from one source in a week before it's worth a look. */
const DMARC_FAILING_MIN = 50;
const _EMAIL_DOCS = "https://developers.cloudflare.com/dns/manage-dns-records/how-to/email-records/";

const txtValue = (r: DnsRecord) => unquote(r.content);

export default defineChecks(
  {
    "EML-001": {
      category: "Email",
      severity: "high",
      docs: "https://developers.cloudflare.com/dns/manage-dns-records/how-to/email-records/",
      requires: ["dnsRecords"],
      title: "SPF missing, duplicated or too permissive",
      why: "Anyone can send mail that passes as this domain.",
      fix: "Publish exactly one SPF TXT record listing your senders and ending in ~all or -all.",
    },
    "EML-002": {
      category: "Email",
      severity: "high",
      docs: "https://developers.cloudflare.com/dmarc-management/",
      requires: ["dnsRecords"],
      title: "DMARC missing or not enforcing",
      why: "Receivers have no instruction to reject spoofed mail from this domain.",
      fix: "Publish _dmarc with p=quarantine or p=reject (start with p=none plus rua reports if you need to discover senders first).",
    },
    "EML-003": {
      category: "Email",
      severity: "low",
      docs: "https://developers.cloudflare.com/dmarc-management/",
      requires: ["dnsRecords"],
      title: "Misnamed DMARC record",
      why: "DMARC is only read from _dmarc.<domain>. This record has no effect.",
      fix: "Delete it; make sure the real _dmarc record has the policy you intended.",
    },
    "EML-004": {
      category: "Email",
      severity: "medium",
      docs: "https://developers.cloudflare.com/dns/manage-dns-records/how-to/email-records/#prevent-domain-spoofing",
      requires: ["dnsRecords"],
      title: "Domain that sends no mail is not locked down",
      why: "Unused domains are favourite spoofing targets because nobody watches them.",
      fix: 'Publish SPF "v=spf1 -all" and DMARC "v=DMARC1; p=reject" (plus a null DKIM key if you want).',
    },
    "EML-005": {
      category: "Email",
      severity: "low",
      docs: "https://developers.cloudflare.com/dmarc-management/",
      requires: ["dnsRecords"],
      title: "DMARC without aggregate reports",
      why: "Without rua reports you can't see who is sending as your domain or whether legitimate mail is failing.",
      fix: "Add rua=mailto:<reports address> to the DMARC record (Cloudflare's free DMARC Management can receive them).",
    },
    "EML-006": {
      category: "Email",
      severity: "medium",
      docs: "https://developers.cloudflare.com/dns/manage-dns-records/how-to/email-records/",
      requires: ["dnsRecords", "doh"],
      title: "SPF exceeds 10 DNS lookups",
      why: "Receivers treat SPF with more than 10 lookups as a permanent error, so legitimate mail can fail.",
      fix: "Remove unused includes or flatten some of them.",
    },
    "EML-007": {
      category: "Email",
      severity: "low",
      docs: "https://developers.cloudflare.com/dns/manage-dns-records/how-to/email-records/",
      requires: ["dnsRecords", "doh"],
      title: "Weak DKIM signing key",
      why: "Keys under 2048 bits are below current recommendations, and keys under 1024 bits can be factored, letting someone forge signed mail.",
      fix: "Generate a 2048-bit key with your mail provider, publish it under a new selector, then retire the old one.",
    },
    "EML-008": {
      category: "Email",
      severity: "low",
      docs: "https://developers.cloudflare.com/dmarc-management/",
      requires: ["dnsRecords", "doh"],
      title: "DMARC reports go to a domain that doesn't accept them",
      why: "Receivers only send reports to another domain if it publishes an authorization record. Without it your reports are silently dropped.",
      fix: 'Ask the report receiver to publish <your-domain>._report._dmarc.<their-domain> TXT "v=DMARC1", or send reports to your own domain.',
    },
    "EML-009": {
      category: "Email",
      severity: "low",
      docs: "https://developers.cloudflare.com/dns/manage-dns-records/how-to/email-records/",
      requires: ["dnsRecords", "doh"],
      title: "Domain receives mail without MTA-STS",
      why: "Without MTA-STS, an attacker on the network path can downgrade mail delivery to plain text.",
      fix: "Publish an MTA-STS policy (_mta-sts TXT record plus the policy file) and a TLS-RPT record (_smtp._tls) for reports.",
    },
    "EML-010": {
      category: "Email",
      severity: "medium",
      docs: "https://developers.cloudflare.com/email-routing/setup/email-routing-addresses/#catch-all-address",
      requires: ["emailRouting"],
      title: "Email Routing forwards every address at the domain",
      why: "A catch-all forwards mail sent to any made-up address, so spam, phishing and password-reset mail for addresses nobody owns all land in one inbox.",
      fix: "Under Email → Email Routing → Routing rules, set the catch-all action to Drop and add explicit addresses for the ones you use.",
    },
    "EML-011": {
      category: "Email",
      severity: "medium",
      docs: "https://developers.cloudflare.com/dmarc-management/",
      requires: ["dmarcReports", "dnsRecords"],
      title: "Mail that fails DMARC is being sent as your domain",
      why: "Receivers report messages using your domain that fail SPF and DKIM. With a p=none policy they're still delivered, so whoever sends them is impersonating you.",
      fix: "1. Check the senders in Email → DMARC Management. 2. Authorize the legitimate ones (SPF include or DKIM). 3. Move the policy to p=quarantine, then p=reject.",
    },
  },
  ({ inv, d }, report) => {
    for (const z of inv.zones) {
      if (!z.dnsReadable) continue;
      const zone = z.name;
      const link = d.zone(zone, "dns/records");
      const byName = groupBy(z.dns, (r) => r.name.toLowerCase());
      const txt = (name: string): string[] => (byName.get(name) || []).filter((r) => r.type === "TXT").map(txtValue);
      const spfAt = (name: string) => txt(name).filter((v) => /^v=spf1(\s|$)/i.test(v));
      const dmarcAt = (name: string) => txt(`_dmarc.${name}`).find((v) => /^v=DMARC1/i.test(v));
      const apexDmarc = dmarcAt(zone);
      const tagsOf = (rec: string): Record<string, string> =>
        Object.fromEntries(
          rec
            .split(";")
            .map((t) =>
              t
                .trim()
                .split("=")
                .map((x) => x?.trim()),
            )
            .filter((t) => t[0]),
        );

      // Names that send or receive mail: anything with MX or SPF.
      const mailNames = [...byName.keys()].filter((n) => !n.startsWith("_") && ((byName.get(n) || []).some((r) => r.type === "MX") || spfAt(n).length));

      const apexMx = (byName.get(zone) || []).some((r) => r.type === "MX");
      const apexSpf = spfAt(zone);
      if (!apexMx && (apexSpf.length === 0 || apexSpf.every((v) => /\s-all$/i.test(v)))) {
        // Domain doesn't handle mail: it should say so explicitly.
        const lockedSpf = apexSpf.length === 1 && /^v=spf1\s+-all$/i.test(apexSpf[0]);
        const lockedDmarc = !!apexDmarc && /p=reject/i.test(apexDmarc);
        report("EML-004", {
          zone,
          resource: zone,
          pass: lockedSpf && lockedDmarc,
          link,
          detail: `No MX records. SPF: ${apexSpf[0] || "none"}. DMARC: ${apexDmarc || "none"}.`,
        });
      } else if (!mailNames.includes(zone)) {
        mailNames.push(zone);
      }

      for (const name of mailNames) {
        const spf = spfAt(name);
        const isApex = name === zone;
        // SPF quality. A missing SPF is only required at the apex; subdomains inherit DMARC.
        let spfProblem: string | null = null;
        if (spf.length === 0 && isApex) spfProblem = "No SPF record.";
        else if (spf.length > 1) spfProblem = `${spf.length} SPF records; receivers treat this as an error.`;
        else if (spf.length === 1 && /[+?]all\b/i.test(spf[0])) spfProblem = `SPF ends permissively: ${spf[0]}`;
        else if (spf.length === 1 && !/[~-]all\b|redirect=/i.test(spf[0])) spfProblem = `SPF has no ~all/-all terminator: ${spf[0]}`;
        if (spf.length || isApex) report("EML-001", { zone, resource: name, pass: !spfProblem, detail: spfProblem || "", link });

        const lookups = inv.spfLookups[name];
        if (lookups != null)
          report("EML-006", {
            zone,
            resource: name,
            pass: lookups <= MAX_SPF_LOOKUPS,
            detail: `SPF needs ${lookups} DNS lookups (limit ${MAX_SPF_LOOKUPS}).`,
            link,
          });

        // DMARC applies to header-From domains; skip custom MAIL FROM / bounce subdomains.
        if (!isApex && MAIL_FROM_LABEL.test(name)) continue;
        const own = dmarcAt(name);
        const effective = own || apexDmarc;
        if (effective) {
          const tags = tagsOf(effective);
          const policy = !own && tags.sp ? tags.sp : tags.p;
          const pct = tags.pct ? Number(tags.pct) : 100;
          const enforcing = ["quarantine", "reject"].includes(String(policy).toLowerCase());
          report("EML-002", {
            zone,
            resource: name,
            pass: enforcing && pct === 100,
            severity: enforcing ? "low" : "medium",
            link,
            detail: !enforcing
              ? `DMARC policy is p=${policy}${own ? "" : ` (inherited from ${zone})`}: spoofed mail is still delivered.`
              : `DMARC applies to only ${pct}% of mail (pct=${pct}).`,
          });
          if (own || isApex) report("EML-005", { zone, resource: name, pass: /rua=/i.test(effective), link });
        } else {
          report("EML-002", { zone, resource: name, pass: false, severity: "high", detail: "No DMARC record at this name or the domain apex.", link });
        }
      }

      // DMARC records published at the wrong name.
      for (const r of z.dns) {
        const n = r.name.toLowerCase();
        if (r.type === "TXT" && /^v=DMARC1/i.test(txtValue(r)) && !n.startsWith("_dmarc.")) {
          report("EML-003", { zone, resource: r.name, pass: false, detail: `Should be at _dmarc.${n.replace(/^dmarc\./, "")}.`, link });
        }
      }

      // DKIM key strength, DMARC report authorization and MTA-STS, from the deeper DNS lookups.
      const zl = zone.toLowerCase();
      const deep = inv.deepDns;
      for (const [name, key] of Object.entries(deep.dkim)) {
        if (!(name === zl || name.endsWith(`.${zl}`)) || !key || key.revoked || key.bits == null) continue;
        report("EML-007", {
          zone,
          resource: name,
          pass: key.bits >= 2048,
          severity: key.bits < 1024 ? "high" : "low",
          link,
          detail: `The ${key.type.toUpperCase()} key published at ${name} is about ${key.bits} bits.`,
        });
      }
      for (const [pair, ok] of Object.entries(deep.dmarcAuth)) {
        const [owner, dom] = pair.split("|");
        if (!(owner === zl || owner.endsWith(`.${zl}`))) continue;
        report("EML-008", {
          zone,
          resource: `${owner} → ${dom}`,
          pass: ok,
          link,
          detail: `_dmarc.${owner} sends aggregate reports to ${dom}, which hasn't published ${owner}._report._dmarc.${dom}${inv.zones.some((x) => x.name.toLowerCase() === dom) ? " (even though both domains are in this account, receivers still require the record)" : ""}.`,
        });
      }
      if (zl in deep.mtaSts) {
        const hasRpt = (byName.get(`_smtp._tls.${zl}`) || []).some((r) => r.type === "TXT");
        report("EML-009", {
          zone,
          resource: zl,
          pass: deep.mtaSts[zl],
          link,
          detail: `${zl} receives mail but publishes no MTA-STS policy${hasRpt ? "" : " and no TLS reporting (TLS-RPT) record"}.`,
        });
      }

      if (z.emailCatchAll) {
        const forwards = z.emailCatchAll.enabled && (z.emailCatchAll.actions || []).some((a) => a.type === "forward");
        report("EML-010", {
          zone,
          resource: zone,
          pass: !forwards,
          link: d.zone(zone, "email/routing/routes"),
          detail: `Mail to any address @${zone} is forwarded to ${(z.emailCatchAll.actions || []).flatMap((a) => a.value || []).join(", ") || "a destination"}.`,
        });
      }

      // EML-011: unauthenticated senders in DMARC aggregate reports while DMARC isn't enforcing.
      const policy = apexDmarc ? String(tagsOf(apexDmarc).p || "none").toLowerCase() : "none";
      const sources = z.analytics?.dmarcSources;
      if (sources?.length && policy === "none") {
        const failing = [
          ...groupBy(
            sources.filter((s) => s.from === zl || s.from.endsWith(`.${zl}`)),
            (s) => s.org,
          ).entries(),
        ]
          .map(([org, rows]) => ({ org, failed: rows.reduce((n, r) => n + Math.max(0, r.total - r.passing), 0) }))
          .filter((x) => x.failed >= DMARC_FAILING_MIN)
          .sort((a, b) => b.failed - a.failed);
        report("EML-011", {
          zone,
          resource: zone,
          pass: failing.length === 0,
          confidence: "likely",
          link: d.zone(zone, "email/dmarc-management"),
          detail: `In the last ${z.analytics!.days} days, receivers reported ${failing.reduce((n, x) => n + x.failed, 0).toLocaleString("en-US")} messages from ${zone} that failed DMARC, sent through ${failing
            .slice(0, 4)
            .map((x) => x.org)
            .join(", ")}${failing.length > 4 ? ` and ${failing.length - 4} more` : ""}. The policy is p=none, so they were delivered.`,
          evidence: failing.length
            ? { chain: failing.slice(0, 8).map((x) => ({ label: x.org, value: `${x.failed.toLocaleString("en-US")} failing messages` })) }
            : null,
        });
      }
    }
  },
);
