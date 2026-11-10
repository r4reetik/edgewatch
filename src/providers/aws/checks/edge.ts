// What faces visitors: CloudFront distributions and load balancers that still
// serve plain HTTP or old TLS versions, distributions without a web ACL, and
// origins that CloudFront reaches without encryption.

import { defineChecks } from "./define.ts";
import { GLOBAL } from "../types.ts";

/** CloudFront security policies that still accept TLS 1.0 or 1.1. */
const OLD_CLOUDFRONT_TLS = new Set(["SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016"]);
/** Load balancer security policies that still accept TLS 1.0 or 1.1, including the long-time default. */
const OLD_ELB_TLS = /^ELBSecurityPolicy-(2015-05|2016-08|TLS-1-[01]-|FS-2018-06|FS-1-1-|TLS13-1-[01]-)/;

export default defineChecks(
  {
    "AED-001": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-viewers-to-cloudfront.html",
      requires: ["cloudfront"],
      title: "CloudFront distribution serves plain HTTP",
      why: "Visitors who arrive over HTTP stay on HTTP, so anyone on their network can read or change what they see, including session cookies.",
      fix: "In CloudFront → the distribution → Behaviors, edit each behavior and set Viewer protocol policy to Redirect HTTP to HTTPS.",
    },
    "AED-002": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html",
      requires: ["cloudfront"],
      title: "CloudFront distribution accepts TLS 1.0 or 1.1",
      why: "TLS 1.0 and 1.1 have known weaknesses and are no longer accepted by PCI DSS or current browsers. Accepting them lets an attacker downgrade a visitor's connection.",
      fix: "In CloudFront → the distribution → Settings → Edit, set Security policy to TLSv1.2_2021 or newer.",
    },
    "AED-003": {
      category: "WAF & bots",
      severity: "low",
      docs: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html",
      requires: ["cloudfront"],
      title: "CloudFront distribution has no web ACL",
      why: "Requests reach the application behind the distribution without AWS WAF looking at them: no managed rules for common attacks, no rate limits, no bot control.",
      fix: "In CloudFront → the distribution → Security, enable AWS WAF protections. Start with the core managed rules and a rate limit. If another WAF sits in front of this distribution (Cloudflare, for example), mark this as accepted.",
    },
    "AED-004": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-custom-origin.html",
      requires: ["cloudfront"],
      title: "CloudFront reaches its origin over plain HTTP",
      why: "The visitor sees a padlock, but the request travels unencrypted between CloudFront and the origin, where it can be read or altered.",
      fix: "Install a certificate on the origin, then in CloudFront → the distribution → Origins, edit the origin and set Protocol to HTTPS only.",
    },
    "AED-005": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-listeners.html#redirect-actions",
      requires: ["loadBalancers"],
      title: "Load balancer serves plain HTTP",
      why: "The internet-facing load balancer answers on HTTP without sending visitors to HTTPS, so their requests and cookies cross the network unencrypted.",
      fix: "In EC2 → Load Balancers → the load balancer → Listeners, edit the HTTP listener's default action to Redirect to HTTPS on port 443.",
    },
    "AED-006": {
      category: "TLS & HTTPS",
      severity: "medium",
      docs: "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html",
      requires: ["loadBalancers"],
      title: "Load balancer accepts TLS 1.0 or 1.1",
      why: "The listener's security policy still negotiates TLS 1.0 or 1.1, which have known weaknesses and fail PCI DSS.",
      fix: "In EC2 → Load Balancers → the load balancer → Listeners, edit the HTTPS listener and choose the recommended policy, ELBSecurityPolicy-TLS13-1-2-2021-06 or newer.",
    },
  },
  ({ inv, d }, report) => {
    for (const x of (inv.distributions ?? []).filter((y) => y.enabled)) {
      const resource = x.aliases[0] ? `${x.aliases[0]} (${x.id})` : `${x.domainName} (${x.id})`;
      const base = { zone: GLOBAL, resource, link: d.distribution(x.id) };
      report("AED-001", { ...base, pass: !x.viewerPolicies.includes("allow-all"), detail: "A behavior allows both HTTP and HTTPS" });
      // Without a custom certificate the policy is fixed by CloudFront and can't be changed.
      if (x.aliases.length && !x.defaultCertificate && x.minTls)
        report("AED-002", { ...base, pass: !OLD_CLOUDFRONT_TLS.has(x.minTls), detail: `Security policy ${x.minTls}` });
      // A distribution that only serves files from S3 has little for a web ACL to protect; one in front of an application does.
      if (x.aliases.length && x.origins.some((o) => !o.s3))
        report("AED-003", { ...base, pass: x.waf, detail: "In front of an application origin, with no web ACL" });
      const plain = x.origins.filter((o) => o.protocolPolicy === "http-only" && !/\.s3-website[.-]/.test(o.domain));
      // S3 website endpoints only speak HTTP, so there is nothing to change there.
      if (x.origins.some((o) => o.protocolPolicy)) report("AED-004", { ...base, pass: !plain.length, detail: plain.map((o) => o.domain).join(", ") });
    }

    for (const r of inv.regions)
      for (const lb of r.loadBalancers ?? []) {
        if (!lb.listeners) continue;
        const base = { zone: r.name, resource: lb.name, link: d.loadBalancers(r.name) };
        if (lb.internetFacing && lb.type === "application") {
          const plain = lb.listeners.filter((l) => l.protocol === "HTTP" && !l.redirects);
          report("AED-005", {
            ...base,
            pass: !plain.length,
            detail: plain.length ? `Port ${plain.map((l) => l.port).join(", ")} forwards HTTP without redirecting` : "",
          });
        }
        const secure = lb.listeners.filter((l) => l.sslPolicy);
        const old = secure.filter((l) => OLD_ELB_TLS.test(l.sslPolicy!));
        if (secure.length) report("AED-006", { ...base, pass: !old.length, detail: [...new Set(old.map((l) => l.sslPolicy))].join(", ") });
      }
  },
);
